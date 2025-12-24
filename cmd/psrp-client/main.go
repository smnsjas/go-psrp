// Command psrp-client is an example PowerShell Remoting client.
//
// Usage:
//
//	psrp-client -server <hostname> -user <username> -pass <password> -script <command>
//
// Example:
//
//	psrp-client -server myserver.domain.com -user admin -pass secret -script "Get-Process"
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/smnsjas/go-psrp/client"
)

func main() {
	// Parse command line flags
	server := flag.String("server", "", "WinRM server hostname")
	username := flag.String("user", "", "Username for authentication")
	password := flag.String("pass", "", "Password for authentication")
	script := flag.String("script", "Get-Process | Select-Object -First 5", "PowerShell script to execute")
	useTLS := flag.Bool("tls", false, "Use HTTPS (port 5986)")
	port := flag.Int("port", 0, "WinRM port (default: 5985 for HTTP, 5986 for HTTPS)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	timeout := flag.Duration("timeout", 60*time.Second, "Operation timeout")
	useNTLM := flag.Bool("ntlm", false, "Use NTLM authentication")

	flag.Parse()

	// Validate required flags
	if *server == "" {
		fmt.Fprintln(os.Stderr, "Error: -server is required")
		flag.Usage()
		os.Exit(1)
	}
	if *username == "" {
		fmt.Fprintln(os.Stderr, "Error: -user is required")
		flag.Usage()
		os.Exit(1)
	}
	if *password == "" {
		fmt.Fprintln(os.Stderr, "Error: -pass is required")
		flag.Usage()
		os.Exit(1)
	}

	// Build configuration
	cfg := client.DefaultConfig()
	cfg.Username = *username
	cfg.Password = *password
	cfg.UseTLS = *useTLS
	cfg.InsecureSkipVerify = *insecure
	cfg.Timeout = *timeout

	if *useNTLM {
		cfg.AuthType = client.AuthNTLM
	}

	// Set port
	if *port != 0 {
		cfg.Port = *port
	} else if *useTLS {
		cfg.Port = 5986
	}

	// Create client
	psrp, err := client.New(*server, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Connect to server
	fmt.Printf("Connecting to %s...\n", psrp.Endpoint())
	if err := psrp.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
		os.Exit(1)
	}
	defer psrp.Close(ctx)

	fmt.Println("Connected!")

	// Execute script
	fmt.Printf("Executing: %s\n", *script)
	fmt.Println("---")

	result, err := psrp.Execute(ctx, *script)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing script: %v\n", err)
		os.Exit(1)
	}

	// Print output
	fmt.Printf("Output:\n%s\n", string(result.Output))

	if result.HadErrors {
		fmt.Fprintf(os.Stderr, "Errors:\n%s\n", string(result.Errors))
		os.Exit(1)
	}
}
