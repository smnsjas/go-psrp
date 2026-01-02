// psrp-demo demonstrates concurrent PowerShell command execution.
//
// Usage:
//
//	psrp-demo -server hostname -user username [-tls] [-ntlm] [-insecure]
//
// The demo runs multiple commands concurrently to demonstrate multiplexing.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"golang.org/x/term"
)

func main() {
	// Parse flags
	server := flag.String("server", "", "Target server hostname")
	user := flag.String("user", "", "Username for authentication")
	domain := flag.String("domain", "", "Domain for NTLM authentication")
	useTLS := flag.Bool("tls", false, "Use HTTPS (port 5986)")
	useNTLM := flag.Bool("ntlm", false, "Use NTLM authentication")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	concurrent := flag.Int("concurrent", 3, "Number of concurrent commands to run")

	// HvSocket (PowerShell Direct) flags
	useHvSocket := flag.Bool("hvsocket", false, "Use Hyper-V Socket (PowerShell Direct) transport")
	vmID := flag.String("vmid", "", "VM GUID for HvSocket connection")
	configName := flag.String("configname", "", "PowerShell configuration name (optional, for HvSocket)")

	flag.Parse()

	if (*server == "" && !*useHvSocket) || *user == "" {
		fmt.Fprintln(os.Stderr, "Usage: psrp-demo -server hostname -user username [-tls] [-ntlm] [-insecure] [-concurrent N]")
		fmt.Fprintln(os.Stderr, "   OR: psrp-demo -hvsocket -vmid <VMID> -user username [-configname name] [-concurrent N]")
		os.Exit(1)
	}

	if *useHvSocket && *vmID == "" {
		fmt.Fprintln(os.Stderr, "Error: -vmid is required when using -hvsocket")
		os.Exit(1)
	}

	// Read password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}
	password := string(passwordBytes)

	// Build config
	cfg := client.DefaultConfig()
	cfg.Username = *user
	cfg.Password = password
	cfg.Domain = *domain
	cfg.UseTLS = *useTLS
	cfg.InsecureSkipVerify = *insecure
	cfg.MaxConcurrentCommands = *concurrent

	if *useTLS {
		cfg.Port = 5986
	}
	if *useNTLM {
		cfg.AuthType = client.AuthNTLM
	}

	// HvSocket transport configuration
	if *useHvSocket {
		cfg.Transport = client.TransportHvSocket
		cfg.VMID = *vmID
		cfg.ConfigurationName = *configName
		cfg.Domain = *domain // Use provided domain or "."
	}

	// Create client
	c, err := client.New(*server, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	// Connect
	ctx := context.Background()
	fmt.Printf("Connecting to %s...\n", c.Endpoint())

	if err := c.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
		os.Exit(1)
	}
	defer c.Close(ctx)

	fmt.Println("Connected!")
	fmt.Printf("\n=== Concurrent Execution Demo (max %d concurrent) ===\n\n", *concurrent)

	// Define test commands
	commands := []struct {
		name   string
		script string
	}{
		{"Get hostname", "$env:COMPUTERNAME"},
		{"Get user", "$env:USERNAME"},
		{"Get date", "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"},
		{"Get PS version", "$PSVersionTable.PSVersion.ToString()"},
		{"Simple math", "1 + 1"},
	}

	// Run commands concurrently
	var wg sync.WaitGroup
	start := time.Now()

	for i, cmd := range commands {
		wg.Add(1)
		go func(idx int, name, script string) {
			defer wg.Done()

			cmdStart := time.Now()
			fmt.Printf("[%d] Starting: %s\n", idx+1, name)

			result, err := c.Execute(ctx, script)
			elapsed := time.Since(cmdStart)

			if err != nil {
				fmt.Printf("[%d] ERROR: %s - %v (%.2fs)\n", idx+1, name, err, elapsed.Seconds())
				return
			}

			// Get first output value
			output := "<no output>"
			if len(result.Output) > 0 {
				output = fmt.Sprintf("%v", result.Output[0])
			}

			fmt.Printf("[%d] Done: %s = %s (%.2fs)\n", idx+1, name, output, elapsed.Seconds())
		}(i, cmd.name, cmd.script)
	}

	wg.Wait()
	totalElapsed := time.Since(start)

	fmt.Printf("\n=== All %d commands completed in %.2fs ===\n", len(commands), totalElapsed.Seconds())

	// If running sequentially, it would take ~5x longer
	// With multiplexing, commands overlap
	fmt.Println("\nMultiplexing allows commands to run in parallel on a single connection!")
}
