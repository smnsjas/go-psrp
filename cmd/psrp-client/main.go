// Command psrp-client is an example PowerShell Remoting client.
//
// Password can be provided via:
//   - -pass flag (least secure, visible in process list)
//   - PSRP_PASSWORD environment variable (recommended)
//   - stdin prompt (if neither flag nor env var is set)
//
// Usage:
//
//	psrp-client -server <hostname> -user <username> -script <command>
//
// Examples:
//
//	# Using environment variable (recommended)
//	export PSRP_PASSWORD='secret'
//	psrp-client -server myserver -user admin -script "Get-Process"
//
//	# Using stdin prompt
//	psrp-client -server myserver -user admin -script "Get-Process"
//	Password: ********
//
//	# Using flag (not recommended, visible in process list)
//	psrp-client -server myserver -user admin -pass secret -script "Get-Process"
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrp/wsman/auth"
	"github.com/smnsjas/go-psrpcore/serialization"
	"golang.org/x/term"
)

// formatBytes converts bytes to human-readable format (KB, MB, GB).
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

func main() {
	// Parse command line flags
	server := flag.String("server", "", "WinRM server hostname")
	username := flag.String("user", "", "Username for authentication")
	password := flag.String("pass", "", "Password (use PSRP_PASSWORD env var instead)")
	script := flag.String("script", "", "PowerShell script to execute")
	useTLS := flag.Bool("tls", false, "Use HTTPS (port 5986)")
	port := flag.Int("port", 0, "WinRM port (default: 5985 for HTTP, 5986 for HTTPS)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	timeout := flag.Duration("timeout", 120*time.Second, "Operation timeout")
	useNTLM := flag.Bool("ntlm", false, "Use NTLM authentication")
	useKerberos := flag.Bool("kerberos", false, "Use Kerberos authentication")
	realm := flag.String("realm", "", "Kerberos realm (e.g., EXAMPLE.COM)")
	krb5Conf := flag.String("krb5conf", "", "Path to krb5.conf file")
	ccache := flag.String("ccache", "", "Path to Kerberos credential cache (e.g. /tmp/krb5cc_1000)")
	spn := flag.String("spn", "", "Service Principal Name for Kerberos (e.g., HTTP/server.domain.com)")

	// HvSocket (PowerShell Direct) flags
	useHvSocket := flag.Bool("hvsocket", false, "Use Hyper-V Socket (PowerShell Direct) transport")
	vmID := flag.String("vmid", "", "VM GUID for HvSocket connection")
	var configName string
	flag.StringVar(&configName, "configname", "", "PowerShell configuration name (e.g. Microsoft.Exchange)")

	subscribe := flag.String("subscribe", "", "WQL query to subscribe to (e.g. 'SELECT * FROM Win32_ProcessStartTrace')")
	domain := flag.String("domain", ".", "Domain for HvSocket auth (use '.' for local accounts)")

	// Session persistence flags
	doDisconnect := flag.Bool("disconnect", false, "Disconnect from shell after execution (instead of closing)")
	reconnectShellID := flag.String("reconnect", "", "Reconnect to existing ShellID")
	sessionID := flag.String("sessionid", "", "Explicit SessionID (uuid:...) for testing persistence")
	poolID := flag.String("poolid", "", "Explicit PoolID (uuid:...) for reconnection")
	listSessions := flag.Bool("list-sessions", false, "List disconnected sessions on server")
	cleanupSessions := flag.Bool("cleanup", false, "Cleanup (remove) disconnected sessions (used with -list-sessions)")
	recoverCommandID := flag.String("recover", "", "Recover output from pipeline with CommandID (requires -reconnect)")
	asyncExec := flag.Bool("async", false, "Start command and disconnect immediately (fire-and-forget)")
	saveSession := flag.String("save-session", "", "Save session state to file on disconnect/exit")
	restoreSession := flag.String("restore-session", "", "Restore session state from file")
	logLevel := flag.String("loglevel", "", "Log level: debug, info, warn, error (empty = no logging)")
	keepAlive := flag.Duration("keepalive", 0, "Keepalive interval (e.g. 30s). 0 to disable.")
	idleTimeout := flag.String("idle-timeout", "", "WSMan shell idle timeout (ISO8601 duration, e.g. PT1H, PT30M)")
	enableCBT := flag.Bool("cbt", false, "Enable Channel Binding Tokens (CBT) for NTLM (Extended Protection)")
	testConcurrency := flag.Int("test-concurrency", 0, "Test semaphore: spawn N concurrent commands (requires -script)")
	maxRunspaces := flag.Int("max-runspaces", 1, "Max concurrent pipelines (default: 1)")
	// Retry flags
	retryAttempts := flag.Int("retry-attempts", 0, "Max command retry attempts (default: 0 = disabled)")
	retryDelay := flag.Duration("retry-delay", 100*time.Millisecond, "Initial retry delay")
	retryMaxDelay := flag.Duration("retry-max-delay", 5*time.Second, "Max retry delay")

	// Circuit Breaker flags
	breakerThreshold := flag.Int("breaker-threshold", 5, "Circuit Breaker failure threshold (0 to disable)")
	breakerTimeout := flag.Duration("breaker-timeout", 30*time.Second, "Circuit Breaker reset timeout")

	// File transfer flags
	copyFile := flag.String("copy", "", "Copy local file to remote (format: local=>remote, e.g. /tmp/file.txt=>C:\\Temp\\file.txt)")
	fetchFile := flag.String("fetch", "", "Fetch remote file to local (format: remote=>local, e.g. C:\\Temp\\file.txt=>/tmp/file.txt)")
	verifyChecksum := flag.Bool("verify", false, "Verify file transfer with SHA256 checksum")
	chunkSize := flag.Int("chunk-size", 0, "File transfer chunk size in bytes (0 = auto-detect based on transport: 350KB for WSMan, 1MB for HvSocket)")
	noOverwrite := flag.Bool("no-overwrite", false, "Fail if destination file already exists")

	autoReconnect := flag.Bool("auto-reconnect", false, "Enable automatic reconnection on failures")
	useCmd := flag.Bool("cmd", false, "Use WinRS (cmd.exe) instead of PowerShell for command execution")

	flag.Parse()

	if *logLevel != "" {
		_ = os.Setenv("PSRP_DEBUG", "1") // Enable legacy debug as well
	}

	fmt.Println("PSRP Client - Codebase Fix v5 (Retry Logic)")

	// Validate required flags
	// If restoring session, we don't need server or vmid flags as they come from the state file
	if *restoreSession == "" {
		if *server == "" && !*useHvSocket {
			fmt.Fprintln(os.Stderr, "Error: -server is required (or use -hvsocket with -vmid)")
			flag.Usage()
			os.Exit(1)
		}
		if *useHvSocket && *vmID == "" {
			fmt.Fprintln(os.Stderr, "Error: -vmid is required when using -hvsocket")
			flag.Usage()
			os.Exit(1)
		}
	}
	// Validate flags
	// Username is required unless the platform supports SSO (e.g. Windows)
	if *username == "" && !auth.SupportsSSO() {
		fmt.Fprintln(os.Stderr,
			"Error: -user is required (SSO not supported on this platform)")
		flag.Usage()
		os.Exit(1)
	}

	// Check for Kerberos cred cache first (SSO)
	var pass string

	// Auto-detect Kerberos cache on macOS if -kerberos is set and no cache specified
	detectedCache := *ccache
	if *useKerberos && detectedCache == "" && os.Getenv("KRB5CCNAME") == "" {
		// Try to detect macOS API cache using klist -l
		out, err := exec.Command("klist", "-l").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			var bestCache string

			for _, line := range lines {
				// Skip headers and empty lines
				if !strings.Contains(line, "API:") {
					continue
				}

				// Check if this line is the active cache (starts with *)
				isActive := strings.TrimSpace(line)[0] == '*'

				// Parse fields to find API: identifier
				fields := strings.Fields(line)
				var apiCache string
				for _, f := range fields {
					if strings.HasPrefix(f, "API:") {
						apiCache = f
						break
					}
				}

				if apiCache == "" {
					continue
				}

				// If active, this is the one we want absolutely.
				if isActive {
					bestCache = apiCache
					break
				}

				// Otherwise, if we haven't found a best one yet, keeping looking,
				// but check if it's expired.
				if bestCache == "" && !strings.Contains(line, ">>> Expired <<<") {
					bestCache = apiCache
				}
			}
			detectedCache = bestCache
		}

		// If we found an API: cache, export it to a temp file (gokrb5 can't read API caches)
		if strings.HasPrefix(detectedCache, "API:") {
			tempCache := fmt.Sprintf("/tmp/psrp_krb5cc_%d", os.Getpid())
			// Use kcc copy to copy credentials from API cache to file cache (Heimdal command)
			// Security: detectedCache comes from parsing local 'klist' output, which is considered a trusted source.
			// #nosec G204 -- klist output is system-generated and trusted for local user context
			cmd := exec.Command("kcc", "copy", detectedCache, tempCache)
			if err := cmd.Run(); err == nil {
				detectedCache = tempCache
			} else {
				// kcc not available, can't use API cache with gokrb5
				detectedCache = ""
			}
		}
	}

	hasCache := (detectedCache != "" || os.Getenv("KRB5CCNAME") != "") && !*useNTLM

	// Get password only if username is provided and no cache (or strict NTLM usage)
	// For SSO (no username), password is not needed
	if *username != "" && !hasCache {
		// Get password from: flag > env var > stdin prompt
		pass = getPassword(*password)
	}

	// Password is required unless: using Kerberos with cache, or explicit -kerberos flag with cache
	// Password is required if username provided, unless: using Kerberos with cache
	// If SSO (no username), password is not required
	// But if strictly HvSocket (which often needs creds) or restoring session where we need creds to reconnect:
	needCreds := *username != "" || (*restoreSession != "" && !hasCache && !auth.SupportsSSO())
	if needCreds && pass == "" && !hasCache {
		fmt.Fprintln(os.Stderr, "Error: password is required (use -pass, PSRP_PASSWORD env, or stdin)")
		os.Exit(1)
	}

	// Build configuration
	cfg := client.DefaultConfig()
	cfg.Username = *username
	cfg.Password = pass
	cfg.UseTLS = *useTLS
	cfg.InsecureSkipVerify = *insecure
	cfg.Timeout = *timeout
	cfg.KeepAliveInterval = *keepAlive
	cfg.IdleTimeout = *idleTimeout
	cfg.EnableCBT = *enableCBT
	cfg.MaxRunspaces = *maxRunspaces
	cfg.Reconnect.Enabled = *autoReconnect

	// Configure Retry Policy
	if *retryAttempts > 0 {
		cfg.Retry = client.DefaultRetryPolicy()
		cfg.Retry.MaxAttempts = *retryAttempts
		if *retryDelay > 0 {
			cfg.Retry.InitialDelay = *retryDelay
		}
		if *retryMaxDelay > 0 {
			cfg.Retry.MaxDelay = *retryMaxDelay
		}
		fmt.Printf("Command Retry: Enabled (attempts=%d, delay=%v, max=%v)\n",
			cfg.Retry.MaxAttempts, cfg.Retry.InitialDelay, cfg.Retry.MaxDelay)
	}

	// Configure Circuit Breaker
	if *breakerThreshold > 0 {
		cfg.CircuitBreaker = client.DefaultCircuitBreakerPolicy()
		cfg.CircuitBreaker.FailureThreshold = *breakerThreshold
		cfg.CircuitBreaker.ResetTimeout = *breakerTimeout
		fmt.Printf("Circuit Breaker: Enabled (threshold=%d, timeout=%v)\n",
			cfg.CircuitBreaker.FailureThreshold, cfg.CircuitBreaker.ResetTimeout)
	} else {
		cfg.CircuitBreaker = &client.CircuitBreakerPolicy{Enabled: false}
		fmt.Println("Circuit Breaker: Disabled")
	}

	// Configure Circuit Breaker
	if *breakerThreshold > 0 {
		cfg.CircuitBreaker = client.DefaultCircuitBreakerPolicy()
		cfg.CircuitBreaker.FailureThreshold = *breakerThreshold
		cfg.CircuitBreaker.ResetTimeout = *breakerTimeout
		fmt.Printf("Circuit Breaker: Enabled (threshold=%d, timeout=%v)\n",
			cfg.CircuitBreaker.FailureThreshold, cfg.CircuitBreaker.ResetTimeout)
	} else {
		cfg.CircuitBreaker = &client.CircuitBreakerPolicy{Enabled: false}
		fmt.Println("Circuit Breaker: Disabled")
	}

	// Kerberos settings apply to both AuthNegotiate (default) and explicit -kerberos
	cfg.Realm = *realm
	cfg.Krb5ConfPath = *krb5Conf
	cfg.CCachePath = detectedCache // Use auto-detected cache if available
	// Default to environment variables if not set
	if cfg.CCachePath == "" {
		cfg.CCachePath = os.Getenv("KRB5CCNAME")
	}
	if cfg.Realm == "" {
		cfg.Realm = os.Getenv("PSRP_REALM")
	}
	if cfg.Krb5ConfPath == "" {
		cfg.Krb5ConfPath = os.Getenv("KRB5_CONFIG")
	}
	cfg.TargetSPN = *spn

	// Override auth type if explicit flag set
	if *useKerberos {
		cfg.AuthType = client.AuthKerberos
	} else if *useNTLM {
		cfg.AuthType = client.AuthNTLM
	}
	// Default is AuthNegotiate (set by DefaultConfig)

	// Set port
	if *port != 0 {
		cfg.Port = *port
	} else if *useTLS {
		cfg.Port = 5986
	}

	// HvSocket transport
	if *useHvSocket {
		cfg.Transport = client.TransportHvSocket
		cfg.VMID = *vmID
		cfg.Domain = *domain
	}

	// Apply ConfigurationName if provided (applies to both WSMan and HvSocket)
	if configName != "" {
		cfg.ConfigurationName = configName
	}

	// Create client
	psrp, err := client.New(*server, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	// Configure structured logging if requested
	// Configure structured logging if requested
	if *logLevel != "" {
		var level slog.Level
		switch strings.ToLower(*logLevel) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			fmt.Fprintf(os.Stderr, "Invalid log level '%s'. Valid values: debug, info, warn, error\n", *logLevel)
			os.Exit(1)
		}

		opts := &slog.HandlerOptions{Level: level}
		logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
		psrp.SetSlogLogger(logger)
	}

	if *sessionID != "" {
		psrp.SetSessionID(*sessionID)
	}
	if *poolID != "" {
		if err := psrp.SetPoolID(*poolID); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid PoolID: %v\n", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Connect to server (or reconnect)
	fmt.Printf("Connecting to %s...\n", psrp.Endpoint())

	// Handle list-sessions mode (doesn't require full connection)
	if *listSessions {
		// Connect to enumerate (creates client but doesn't fully connect)
		if err := psrp.Connect(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
			os.Exit(1)
		}
		defer psrp.Close(ctx)

		sessions, err := psrp.ListDisconnectedSessions(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing sessions: %v\n", err)
			os.Exit(1)
		}

		if len(sessions) == 0 {
			fmt.Println("No disconnected sessions found.")
		} else {
			fmt.Printf("Found %d session(s):\n", len(sessions))
			for i, s := range sessions {
				fmt.Printf("\n%d. ShellID: %s\n", i+1, s.ShellID)
				if s.Name != "" {
					fmt.Printf("   Name: %s\n", s.Name)
				}
				if s.State != "" {
					fmt.Printf("   State: %s\n", s.State)
				}
				if s.Owner != "" {
					fmt.Printf("   Owner: %s\n", s.Owner)
				}
				if len(s.Pipelines) > 0 {
					fmt.Printf("   Pipelines (%d):\n", len(s.Pipelines))
					for _, p := range s.Pipelines {
						fmt.Printf("     - CommandID: %s\n", p.CommandID)
					}
				}
			}
		}

		if *cleanupSessions && len(sessions) > 0 {
			fmt.Println("\nCleaning up...")
			for _, s := range sessions {
				fmt.Printf("Removing session %s... ", s.ShellID)
				if err := psrp.RemoveDisconnectedSession(ctx, s); err != nil {
					fmt.Printf("Failed: %v\n", err)
				} else {
					fmt.Println("Done")
				}
			}
		}
		return
	}

	if *reconnectShellID != "" {
		// Reconnect to existing shell
		fmt.Printf("Reconnecting to shell %s...\n", *reconnectShellID)
		if err := psrp.Reconnect(ctx, *reconnectShellID); err != nil {
			fmt.Fprintf(os.Stderr, "Error reconnecting: %v\n", err)
			os.Exit(1)
		}
	} else if *restoreSession != "" {
		// Restore session from file
		fmt.Printf("Restoring session from %s...\n", *restoreSession)
		state, err := client.LoadState(*restoreSession)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading session state: %v\n", err)
			os.Exit(1)
		}

		if err := psrp.ReconnectSession(ctx, state); err != nil {
			fmt.Fprintf(os.Stderr, "Error restoring session: %v\n", err)
			os.Exit(1)
		}

		if len(state.PipelineIDs) > 0 {
			fmt.Printf("Restored session with active pipelines:\n")
			for _, pid := range state.PipelineIDs {
				fmt.Printf(" - %s\n", pid)
			}
			// Auto-use first pipeline ID if -recover flag is present but empty
			if *recoverCommandID == "" {
				*recoverCommandID = state.PipelineIDs[0]
				fmt.Printf("Auto-recovering pipeline: %s\n", *recoverCommandID)
			}
		}

		if len(state.OutputPaths) > 0 {
			fmt.Printf("Restored session with file recovery paths:\n")
			for cmdID := range state.OutputPaths {
				fmt.Printf(" - %s\n", cmdID)
				if *recoverCommandID == "" {
					*recoverCommandID = cmdID
					fmt.Printf("Auto-recovering pipeline: %s\n", *recoverCommandID)
				}
			}
		}
	} else {
		// Create new session
		if *useCmd {
			// WinRS mode - just connect WSMan, skip PSRP runspace
			if err := psrp.ConnectWSManOnly(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Error connecting (WinRS): %v\n", err)
				os.Exit(1)
			}
		} else {
			// PowerShell mode - full PSRP connection
			if err := psrp.Connect(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Defer Close ONLY if we are NOT disconnecting and not async
	if !*doDisconnect && !*asyncExec {
		defer psrp.Close(ctx)
	}

	fmt.Println("Connected!")
	if !*useCmd {
		// Only show PSRP state for PowerShell mode
		fmt.Printf("State: %s\n", psrp.State())
		fmt.Printf("Health: %s\n", psrp.Health())
	}

	// Handle recovery
	if *recoverCommandID != "" {
		shellID := *reconnectShellID
		if shellID == "" {
			shellID = psrp.ShellID()
		}
		// For HvSocket, we use PoolID as ShellID fallback
		if shellID == "" {
			shellID = psrp.PoolID()
		}

		fmt.Printf("Recovering output from shell %s, command %s...\n", shellID, *recoverCommandID)
		result, err := psrp.RecoverPipelineOutput(ctx, shellID, *recoverCommandID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error recovering output: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Recovered Output:")
		for _, obj := range result.Output {
			fmt.Println(formatObject(obj))
		}
		if result.HadErrors {
			fmt.Fprintln(os.Stderr, "Errors:")
			for _, obj := range result.Errors {
				fmt.Fprintln(os.Stderr, formatObject(obj))
			}
		}
		return
	}

	// Handle async execution - start command and disconnect immediately
	if *asyncExec {
		fmt.Printf("Starting async execution: %s\n", *script)
		commandID, err := psrp.ExecuteAsync(ctx, *script)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting async execution: %v\n", err)
			os.Exit(1)
		}

		shellID := psrp.ShellID()
		poolIDVal := psrp.PoolID()
		fmt.Println("---")
		fmt.Println("Command started in background!")
		fmt.Printf("ShellID: %s\n", shellID)
		fmt.Printf("PoolID: %s\n", poolIDVal)
		fmt.Printf("CommandID: %s\n", commandID)

		// Save session if requested
		if *saveSession != "" {
			fmt.Printf("Saving session state to %s...\n", *saveSession)
			if err := psrp.SaveState(*saveSession); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
			}
		}

		// Disconnect the shell
		if err := psrp.Disconnect(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error disconnecting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\nDisconnected! Command continues running on server.")
		fmt.Println("To recover output later, run:")
		fmt.Printf("  ./psrp-client ... -reconnect %s -recover %s -poolid %q\n", shellID, commandID, poolIDVal)
		return
	}

	// Handle file copy (upload)
	if *copyFile != "" {
		parts := strings.SplitN(*copyFile, "=>", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			fmt.Fprintln(os.Stderr, "Error: -copy format is 'local=>remote' (e.g. /tmp/file.txt=>C:\\Temp\\file.txt)")
			os.Exit(1)
		}
		localPath, remotePath := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		// Get file size for summary
		fileInfo, err := os.Stat(localPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error accessing file: %v\n", err)
			os.Exit(1)
		}
		fileSize := fileInfo.Size()

		fmt.Printf("Copying %s -> %s (%s)...\n", localPath, remotePath, formatBytes(fileSize))

		var opts []client.FileTransferOption
		if *verifyChecksum {
			opts = append(opts, client.WithChecksumVerification(true))
		}
		if *chunkSize > 0 {
			opts = append(opts, client.WithChunkSize(*chunkSize))
		}
		if *noOverwrite {
			opts = append(opts, client.WithNoOverwrite(true))
		}

		// Track duration
		startTime := time.Now()

		// Use background context for file transfer - per-chunk timeouts handle slow operations
		// This allows large file transfers to complete without an artificial overall deadline
		if err := psrp.CopyFile(context.Background(), localPath, remotePath, opts...); err != nil {
			fmt.Fprintf(os.Stderr, "Error copying file: %v\n", err)
			os.Exit(1)
		}

		duration := time.Since(startTime)
		speed := float64(fileSize) / duration.Seconds() / 1024 / 1024 // MB/s

		// Output summary
		fmt.Printf("File copied successfully!\n")
		fmt.Printf("  Size: %s\n", formatBytes(fileSize))
		fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))
		fmt.Printf("  Speed: %.2f MB/s\n", speed)
		if *verifyChecksum {
			fmt.Printf("  Checksum: verified ✓\n")
		}
		return
	}

	// Handle file fetch (download)
	if *fetchFile != "" {
		parts := strings.SplitN(*fetchFile, "=>", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			fmt.Fprintln(os.Stderr, "Error: -fetch format is 'remote=>local' (e.g. C:\\Temp\\file.txt=>/tmp/file.txt)")
			os.Exit(1)
		}
		remotePath, localPath := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		fmt.Printf("Fetching %s -> %s...\n", remotePath, localPath)

		var opts []client.FileTransferOption
		if *verifyChecksum {
			opts = append(opts, client.WithChecksumVerification(true))
		}
		if *chunkSize > 0 {
			opts = append(opts, client.WithChunkSize(*chunkSize))
		}

		// Track duration
		startTime := time.Now()

		// Use background context for file transfer - per-chunk timeouts handle slow operations
		if err := psrp.FetchFile(context.Background(), remotePath, localPath, opts...); err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching file: %v\n", err)
			os.Exit(1)
		}

		duration := time.Since(startTime)

		// Get downloaded file size
		fileInfo, _ := os.Stat(localPath)
		var fileSize int64
		if fileInfo != nil {
			fileSize = fileInfo.Size()
		}

		speed := float64(fileSize) / duration.Seconds() / 1024 / 1024 // MB/s

		// Output summary
		fmt.Printf("File fetched successfully!\n")
		if fileSize > 0 {
			fmt.Printf("  Size: %s\n", formatBytes(fileSize))
		}
		fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))
		if fileSize > 0 {
			fmt.Printf("  Speed: %.2f MB/s\n", speed)
		}
		if *verifyChecksum {
			fmt.Printf("  Checksum: verified ✓\n")
		}
		return
	}

	// Handle test-concurrency mode
	if *testConcurrency > 0 {
		fmt.Printf("Testing semaphore with %d concurrent commands (MaxRunspaces=%d)...\n", *testConcurrency, *maxRunspaces)
		fmt.Println("---")

		var wg sync.WaitGroup
		results := make(chan string, *testConcurrency)

		for i := 0; i < *testConcurrency; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				start := time.Now()
				cmdScript := fmt.Sprintf("'Worker %d started'; Start-Sleep 2; 'Worker %d done'", id, id)
				result, err := psrp.Execute(ctx, cmdScript)
				elapsed := time.Since(start)
				if err != nil {
					results <- fmt.Sprintf("Worker %d: ERROR after %v - %v", id, elapsed, err)
				} else {
					results <- fmt.Sprintf("Worker %d: OK after %v - %d outputs", id, elapsed, len(result.Output))
				}
			}(i)
		}

		// Wait for all workers and close channel
		go func() {
			wg.Wait()
			close(results)
		}()

		// Print results as they arrive
		for r := range results {
			fmt.Println(r)
		}
		fmt.Println("---")
		fmt.Println("If MaxRunspaces < test-concurrency, some workers should take longer (queued).")
		return
	}

	// Handle Subscription Mode
	if *subscribe != "" {
		fmt.Printf("Subscribing to events with query: %s\n", *subscribe)

		// Subscribe using the initialized client
		sub, err := psrp.Subscribe(context.Background(), *subscribe)
		if err != nil {
			fmt.Printf("Error subscribing: %v\n", err)
			os.Exit(1)
		}
		defer sub.Close()

		fmt.Println("Subscription active. Waiting for events (Ctrl+C to exit)...")

		for {
			select {
			case event, ok := <-sub.Events:
				if !ok {
					fmt.Println("Event channel closed.")
					return
				}
				fmt.Printf("--- EVENT RECEIVED ---\n%s\n----------------------\n", string(event))
			case err, ok := <-sub.Errors:
				if !ok {
					return
				}
				fmt.Printf("Error: %v\n", err)
			}
		}
	}

	// Normal Execution Mode
	if *script != "" {
		fmt.Printf("Executing: %s\n", *script)
		fmt.Println("---")

		if *useCmd {
			// WinRS (cmd.exe) execution
			cmdResult, err := psrp.ExecuteCmd(ctx, *script)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
				os.Exit(1)
			}

			// Print stdout
			if cmdResult.Stdout != "" {
				fmt.Println("Output:")
				fmt.Print(cmdResult.Stdout)
			}

			// Print stderr
			if cmdResult.Stderr != "" {
				fmt.Println("Errors:")
				fmt.Print(cmdResult.Stderr)
			}

			// Print exit code
			fmt.Printf("\nExit Code: %d\n", cmdResult.ExitCode)

			if cmdResult.ExitCode != 0 {
				os.Exit(cmdResult.ExitCode)
			}
		} else {
			// PowerShell (PSRP) execution
			result, err := psrp.Execute(ctx, *script)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error executing script: %v\n", err)
				os.Exit(1)
			}

			// Print output - format each object for display
			fmt.Println("Output:")
			for _, obj := range result.Output {
				fmt.Println(formatObject(obj))
			}

			// Print information stream (Write-Host output)
			if len(result.Information) > 0 {
				fmt.Println("Information:")
				for _, obj := range result.Information {
					fmt.Println(formatObject(obj))
				}
			}

			// Print warnings
			if len(result.Warnings) > 0 {
				fmt.Println("Warnings:")
				for _, obj := range result.Warnings {
					fmt.Println(formatObject(obj))
				}
			}

			// Print verbose
			if len(result.Verbose) > 0 {
				fmt.Println("Verbose:")
				for _, obj := range result.Verbose {
					fmt.Println(formatObject(obj))
				}
			}

			// Print debug
			if len(result.Debug) > 0 {
				fmt.Println("Debug:")
				for _, obj := range result.Debug {
					fmt.Println(formatObject(obj))
				}
			}

			if result.HadErrors {
				fmt.Fprintln(os.Stderr, "Errors:")
				for _, obj := range result.Errors {
					fmt.Fprintln(os.Stderr, formatObject(obj))
				}
				os.Exit(1)
			}
		}
	}

	// Handle Disconnect
	if *doDisconnect {
		shellID := psrp.ShellID()
		poolIDVal := psrp.PoolID()
		fmt.Printf("\nDisconnecting from shell: %s (PoolID: %s)\n", shellID, poolIDVal)

		if *saveSession != "" {
			fmt.Printf("Saving session state to %s...\n", *saveSession)
			if err := psrp.SaveState(*saveSession); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
			}
		}

		if err := psrp.Disconnect(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error disconnecting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Disconnected successfully. You can reconnect using:")
		if *sessionID != "" {
			fmt.Printf("  ./psrp-client -server %s -user %s -tls -ntlm -insecure -reconnect %s -sessionid %q -poolid %q -script \"Write-Host 'Back'\"\n", *server, *username, shellID, *sessionID, poolIDVal)
		} else {
			fmt.Printf("  -reconnect %s -poolid %s\n", shellID, poolIDVal)
		}
	}
}

// getPassword returns password from flag, env var, or prompts for it.
func getPassword(flagValue string) string {
	// 1. Check flag
	if flagValue != "" {
		return flagValue
	}

	// 2. Check environment variable
	if envPass := os.Getenv("PSRP_PASSWORD"); envPass != "" {
		return envPass
	}

	// 3. Prompt for password (hide input if terminal)
	fmt.Fprint(os.Stderr, "Password: ")

	// Use os.Stdin.Fd() cast to int for cross-platform compatibility
	// (syscall.Stdin is type-specific per OS)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		// Terminal: read password without echo
		passBytes, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // newline after password
		if err != nil {
			return ""
		}
		return string(passBytes)
	}

	// Not a terminal (piped input): read line
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

// formatObject converts a deserialized CLIXML object to a human-readable string.
func formatObject(v interface{}) string {
	if v == nil {
		return "<nil>"
	}
	switch val := v.(type) {
	case string:
		// Decode XML-encoded CRLF (from PowerShell/CLIXML) for cleaner display
		result := val
		result = strings.ReplaceAll(result, "_x000D__x000A_", "\n")
		result = strings.ReplaceAll(result, "_x000D_", "\r")
		result = strings.ReplaceAll(result, "_x000A_", "\n")
		return result
	case *serialization.PSObject:
		// For PSObjects, use ToString if available, otherwise format properties
		if val.ToString != "" {
			return val.ToString
		}
		if val.Value != nil {
			return formatObject(val.Value)
		}
		// Fallback: format as key=value pairs with recursive formatting
		var parts []string
		for k, prop := range val.Properties {
			parts = append(parts, fmt.Sprintf("%s=%s", k, formatObject(prop)))
		}
		return strings.Join(parts, " ")
	case []interface{}:
		// Format slices recursively
		var items []string
		for _, item := range val {
			items = append(items, formatObject(item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	case bool:
		return fmt.Sprintf("%t", val)
	case int32, int64, float64:
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", v)
	}
}
