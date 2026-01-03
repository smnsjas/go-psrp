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
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrp/wsman/auth"
	"github.com/smnsjas/go-psrpcore/serialization"
	"golang.org/x/term"
)

func main() {
	// Parse command line flags
	server := flag.String("server", "", "WinRM server hostname")
	username := flag.String("user", "", "Username for authentication")
	password := flag.String("pass", "", "Password (use PSRP_PASSWORD env var instead)")
	script := flag.String("script", "Get-Process | Select-Object -First 5", "PowerShell script to execute")
	useTLS := flag.Bool("tls", false, "Use HTTPS (port 5986)")
	port := flag.Int("port", 0, "WinRM port (default: 5985 for HTTP, 5986 for HTTPS)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	timeout := flag.Duration("timeout", 60*time.Second, "Operation timeout")
	useNTLM := flag.Bool("ntlm", false, "Use NTLM authentication")
	useKerberos := flag.Bool("kerberos", false, "Use Kerberos authentication")
	realm := flag.String("realm", "", "Kerberos realm (e.g., EXAMPLE.COM)")
	krb5Conf := flag.String("krb5conf", "", "Path to krb5.conf file")
	ccache := flag.String("ccache", "", "Path to Kerberos credential cache (e.g. /tmp/krb5cc_1000)")

	// HvSocket (PowerShell Direct) flags
	useHvSocket := flag.Bool("hvsocket", false, "Use Hyper-V Socket (PowerShell Direct) transport")
	vmID := flag.String("vmid", "", "VM GUID for HvSocket connection")
	configName := flag.String("configname", "", "PowerShell configuration name (optional, for HvSocket)")
	domain := flag.String("domain", ".", "Domain for HvSocket auth (use '.' for local accounts)")

	// Session persistence flags
	doDisconnect := flag.Bool("disconnect", false, "Disconnect from shell after execution (instead of closing)")
	reconnectShellID := flag.String("reconnect", "", "Reconnect to existing ShellID")
	sessionID := flag.String("sessionid", "", "Explicit SessionID (uuid:...) for testing persistence")
	poolID := flag.String("poolid", "", "Explicit PoolID (uuid:...) for reconnection")
	listSessions := flag.Bool("list-sessions", false, "List disconnected sessions on server")
	recoverCommandID := flag.String("recover", "", "Recover output from pipeline with CommandID (requires -reconnect)")
	asyncExec := flag.Bool("async", false, "Start command and disconnect immediately (fire-and-forget)")

	flag.Parse()

	// Validate required flags
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
			for _, line := range lines {
				// Look for API: cache entries (first non-header line with API:)
				if strings.Contains(line, "API:") {
					fields := strings.Fields(line)
					for _, f := range fields {
						if strings.HasPrefix(f, "API:") {
							detectedCache = f
							break
						}
					}
					if detectedCache != "" {
						break
					}
				}
			}
		}

		// If we found an API: cache, export it to a temp file (gokrb5 can't read API caches)
		if strings.HasPrefix(detectedCache, "API:") {
			tempCache := fmt.Sprintf("/tmp/psrp_krb5cc_%d", os.Getpid())
			// Use kcc copy to copy credentials from API cache to file cache (Heimdal command)
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
	if *username != "" && pass == "" && !hasCache {
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
		cfg.ConfigurationName = *configName
		cfg.Domain = *domain
	}

	// Create client
	psrp, err := client.New(*server, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
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
			return
		}

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
		return
	}

	if *reconnectShellID != "" {
		// Check if we're recovering output from a pipeline
		if *recoverCommandID != "" {
			fmt.Printf("Recovering output from shell %s, command %s...\n", *reconnectShellID, *recoverCommandID)
			result, err := psrp.RecoverPipelineOutput(ctx, *reconnectShellID, *recoverCommandID)
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

		// Reconnect to existing shell
		fmt.Printf("Reconnecting to shell %s...\n", *reconnectShellID)
		if err := psrp.Reconnect(ctx, *reconnectShellID); err != nil {
			fmt.Fprintf(os.Stderr, "Error reconnecting: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Create new session
		if err := psrp.Connect(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
			os.Exit(1)
		}
	}

	// Defer Close ONLY if we are NOT disconnecting and not async
	if !*doDisconnect && !*asyncExec {
		defer psrp.Close(ctx)
	}

	fmt.Println("Connected!")

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

	// Execute script (sync)
	fmt.Printf("Executing: %s\n", *script)
	fmt.Println("---")

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

	// Handle Disconnect
	if *doDisconnect {
		shellID := psrp.ShellID()
		poolIDVal := psrp.PoolID()
		fmt.Printf("\nDisconnecting from shell: %s (PoolID: %s)\n", shellID, poolIDVal)

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
