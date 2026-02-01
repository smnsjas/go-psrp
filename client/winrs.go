package client

import (
	"context"
	"fmt"

	"github.com/smnsjas/go-psrp/winrs"
)

// CmdResult holds the result of a WinRS command execution.
type CmdResult struct {
	// Stdout is the standard output from the command.
	Stdout string
	// Stderr is the standard error from the command.
	Stderr string
	// ExitCode is the command's exit code.
	ExitCode int
}

// ExecuteCmd executes a command via WinRS (cmd.exe) instead of PowerShell.
// This is faster for simple commands as it avoids PSRP protocol overhead.
//
// The command string is passed directly to cmd.exe. For example:
//
//	result, err := c.ExecuteCmd(ctx, "dir /b C:\\Windows")
func (c *Client) ExecuteCmd(ctx context.Context, command string) (*CmdResult, error) {
	c.logInfo("ExecuteCmd called: '%s'", sanitizeScriptForLogging(command))

	// Security Logging (NIST SP 800-92) - Log command attempt
	if c.securityLogger != nil {
		c.securityLogger.LogCommand("winrs_execute", OutcomeAttempt, SeverityInfo, map[string]any{
			"command": sanitizeScriptForLogging(command),
			"mode":    "winrs",
		})
	}

	// Ensure we have a WSMan client
	if c.wsman == nil {
		if c.securityLogger != nil {
			c.securityLogger.LogCommand("winrs_execute", OutcomeFailure, SeverityError, map[string]any{
				"error": "wsman client not initialized",
			})
		}
		return nil, fmt.Errorf("winrs: wsman client not initialized - call ConnectWSManOnly() first")
	}

	// Create a temporary WinRS shell
	shell, err := winrs.NewShell(ctx, c.wsman)
	if err != nil {
		if c.securityLogger != nil {
			c.securityLogger.LogCommand("winrs_execute", OutcomeFailure, SeverityError, map[string]any{
				"error": err.Error(),
				"stage": "create_shell",
			})
		}
		return nil, fmt.Errorf("winrs: create shell: %w", err)
	}
	defer func() {
		if closeErr := shell.Close(ctx); closeErr != nil {
			c.logWarn("winrs: failed to close shell: %v", closeErr)
		}
	}()

	// Run the command through cmd.exe /c
	proc, err := shell.Run(ctx, "cmd.exe", "/c", command)
	if err != nil {
		if c.securityLogger != nil {
			c.securityLogger.LogCommand("winrs_execute", OutcomeFailure, SeverityError, map[string]any{
				"error": err.Error(),
				"stage": "run_command",
			})
		}
		return nil, fmt.Errorf("winrs: run command: %w", err)
	}

	// Security Logging - Log command completion
	if c.securityLogger != nil {
		outcome := OutcomeSuccess
		severity := SeverityInfo
		if proc.ExitCode() != 0 {
			outcome = OutcomeFailure
			severity = SeverityWarning
		}
		c.securityLogger.LogCommand("winrs_complete", outcome, severity, map[string]any{
			"exit_code": proc.ExitCode(),
			"mode":      "winrs",
		})
	}

	return &CmdResult{
		Stdout:   string(proc.Stdout()),
		Stderr:   string(proc.Stderr()),
		ExitCode: proc.ExitCode(),
	}, nil
}

// ConnectWSManOnly initializes the WSMan transport without creating a PSRP runspace.
// Use this for WinRS (cmd.exe) operations that don't need PowerShell.
// This is faster than Connect() as it skips PSRP protocol negotiation.
func (c *Client) ConnectWSManOnly(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("client is closed")
	}

	// Already connected
	if c.wsman != nil {
		return nil
	}

	c.ensureLogger()
	c.logInfoLocked("Initializing WSMan-only connection for WinRS")

	// The wsman client should already be created by New() for WSMan transport
	// We just need to mark it as connected without creating PSRP runspace
	if c.wsman == nil {
		return fmt.Errorf("wsman client not initialized - ensure transport is WSMan")
	}

	c.connected = true
	return nil
}

// CmdStreamResult holds streaming results from a WinRS command.
type CmdStreamResult struct {
	// Stdout is a channel that receives stdout chunks.
	Stdout <-chan []byte
	// Stderr is a channel that receives stderr chunks.
	Stderr <-chan []byte
	// Done is a channel that closes when the command completes.
	Done <-chan struct{}
	// shell is kept for cleanup
	shell *winrs.Shell
	// proc is kept for results
	proc *winrs.Process
}

// ExitCode returns the command's exit code after Done is closed.
func (r *CmdStreamResult) ExitCode() int {
	if r.proc == nil {
		return -1
	}
	return r.proc.ExitCode()
}

// Close terminates the command and releases resources.
func (r *CmdStreamResult) Close(ctx context.Context) error {
	if r.shell != nil {
		return r.shell.Close(ctx)
	}
	return nil
}

// ExecuteCmdStream executes a command via WinRS with streaming output.
// Unlike ExecuteCmd, this returns channels for real-time output processing.
//
// The shell is automatically closed when the command completes or context is cancelled.
// Calling Close() is still recommended to ensure cleanup, but is safe to call multiple times.
//
// Example:
//
//	stream, err := c.ExecuteCmdStream(ctx, "ping -n 10 localhost")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer stream.Close(ctx)
//
//	for {
//	    select {
//	    case chunk := <-stream.Stdout:
//	        fmt.Print(string(chunk))
//	    case <-stream.Done:
//	        return
//	    }
//	}
func (c *Client) ExecuteCmdStream(ctx context.Context, command string) (*CmdStreamResult, error) {
	c.logInfo("ExecuteCmdStream called: '%s'", sanitizeScriptForLogging(command))

	// Ensure we have a WSMan client
	if c.wsman == nil {
		return nil, fmt.Errorf("winrs: wsman client not initialized - call Connect() first")
	}

	// Create a WinRS shell (caller is responsible for closing via CmdStreamResult.Close)
	shell, err := winrs.NewShell(ctx, c.wsman)
	if err != nil {
		return nil, fmt.Errorf("winrs: create shell: %w", err)
	}

	// Start the command
	proc, err := shell.Start(ctx, "cmd.exe", "/c", command)
	if err != nil {
		if closeErr := shell.Close(ctx); closeErr != nil {
			c.logWarn("winrs: failed to close shell after start error: %v", closeErr)
		}
		return nil, fmt.Errorf("winrs: start command: %w", err)
	}

	// Create output channels
	stdoutCh := make(chan []byte, 16)
	stderrCh := make(chan []byte, 16)
	doneCh := make(chan struct{})

	// Stream output in a goroutine
	go func() {
		defer close(stdoutCh)
		defer close(stderrCh)
		defer close(doneCh)
		// Ensure shell is cleaned up when goroutine exits (prevents memory leak)
		defer func() {
			if closeErr := shell.Close(context.Background()); closeErr != nil {
				c.logWarn("winrs: failed to close shell on goroutine exit: %v", closeErr)
			}
		}()

		for {
			// Check context cancellation before each receive
			select {
			case <-ctx.Done():
				c.logInfo("winrs: context cancelled, closing stream")
				return
			default:
			}

			result, err := c.wsman.Receive(ctx, shell.EPR(), proc.CommandID())
			if err != nil {
				c.logWarn("winrs: receive error: %v", err)
				return
			}

			if len(result.Stdout) > 0 {
				stdoutCh <- result.Stdout
			}
			if len(result.Stderr) > 0 {
				stderrCh <- result.Stderr
			}

			if result.Done {
				proc.SetResult(result)
				return
			}
		}
	}()

	return &CmdStreamResult{
		Stdout: stdoutCh,
		Stderr: stderrCh,
		Done:   doneCh,
		shell:  shell,
		proc:   proc,
	}, nil
}
