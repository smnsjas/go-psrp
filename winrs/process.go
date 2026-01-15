package winrs

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/smnsjas/go-psrp/wsman"
)

// Process represents a command running in a WinRS shell.
type Process struct {
	shell     *Shell
	commandID string
	stdout    []byte
	stderr    []byte
	exitCode  int
	done      bool
	mu        sync.Mutex
}

// Run executes a command and waits for completion.
// The executable is the command to run (e.g., "dir", "ping").
// Args are passed as space-separated arguments.
func (s *Shell) Run(ctx context.Context, executable string, args ...string) (*Process, error) {
	proc, err := s.Start(ctx, executable, args...)
	if err != nil {
		return nil, err
	}

	if err := proc.Wait(ctx); err != nil {
		return nil, err
	}

	return proc, nil
}

// Start executes a command without waiting for completion.
// Use Wait() to block until the process finishes.
func (s *Shell) Start(ctx context.Context, executable string, args ...string) (*Process, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrShellClosed
	}
	s.mu.Unlock()

	if executable == "" {
		return nil, ErrInvalidExecutable
	}

	// Join args into a single string
	arguments := strings.Join(args, " ")

	// Create the command
	// For WinRS: executable goes in <rsp:Command>, arguments in <rsp:Arguments>
	// The wsman.Client.Command detects WinRS from ResourceURI and handles this correctly
	returnedID, err := s.transport.Command(ctx, s.epr, executable, arguments)
	if err != nil {
		return nil, fmt.Errorf("winrs: start command: %w", err)
	}

	return &Process{
		shell:     s,
		commandID: returnedID,
	}, nil
}

// Wait blocks until the process completes.
func (p *Process) Wait(ctx context.Context) error {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	for {
		result, err := p.shell.transport.Receive(ctx, p.shell.epr, p.commandID)
		if err != nil {
			return fmt.Errorf("winrs: receive output: %w", err)
		}

		p.mu.Lock()
		p.stdout = append(p.stdout, result.Stdout...)
		p.stderr = append(p.stderr, result.Stderr...)
		p.exitCode = result.ExitCode

		if result.Done {
			p.done = true
			p.mu.Unlock()
			return nil
		}
		p.mu.Unlock()

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

// Send sends data to the process's stdin.
// Returns ErrProcessDone if the process has already completed.
func (p *Process) Send(ctx context.Context, data []byte) error {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return ErrProcessDone
	}
	p.mu.Unlock()

	if err := p.shell.transport.Send(ctx, p.shell.epr, p.commandID, "stdin", data); err != nil {
		return fmt.Errorf("winrs: send input: %w", err)
	}
	return nil
}

// Signal sends a signal to the process.
// Use wsman.SignalTerminate, wsman.SignalCtrlC, or wsman.SignalCtrlBreak.
func (p *Process) Signal(ctx context.Context, code string) error {
	if err := p.shell.transport.Signal(ctx, p.shell.epr, p.commandID, code); err != nil {
		return fmt.Errorf("winrs: signal: %w", err)
	}
	return nil
}

// CommandID returns the command ID.
func (p *Process) CommandID() string {
	return p.commandID
}

// Done returns true if the process has completed.
func (p *Process) Done() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

// Stdout returns the captured standard output. Safe to call after Wait() completes.
func (p *Process) Stdout() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stdout
}

// Stderr returns the captured standard error. Safe to call after Wait() completes.
func (p *Process) Stderr() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stderr
}

// ExitCode returns the process exit code. Safe to call after Wait() completes.
func (p *Process) ExitCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitCode
}

// SetResult sets the process result from a receive operation (for streaming).
// This is an internal method used by ExecuteCmdStream for real-time output.
func (p *Process) SetResult(result *wsman.ReceiveResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stdout = append(p.stdout, result.Stdout...)
	p.stderr = append(p.stderr, result.Stderr...)
	p.exitCode = result.ExitCode
	p.done = result.Done
}
