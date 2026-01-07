package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"golang.org/x/term"
)

func main() {
	server := flag.String("server", "", "Remote server hostname")
	username := flag.String("user", "", "Username (user@domain)")
	password := flag.String("pass", "", "Password (optional, will prompt if missing)")
	useTLS := flag.Bool("tls", false, "Use HTTPS")
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	ntlm := flag.Bool("ntlm", false, "Force NTLM auth (deprecated flag, ignoring)")

	flag.Parse()

	if *server == "" || *username == "" {
		fmt.Println("Usage: go run main.go -server <host> -user <user> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	pass := getPassword(*password)

	cfg := client.DefaultConfig()
	cfg.Username = *username
	cfg.Password = pass
	cfg.UseTLS = *useTLS
	cfg.InsecureSkipVerify = *insecure
	_ = ntlm // Ignored

	if *useTLS {
		cfg.Port = 5986
	}

	fmt.Printf("Creating client to %s...\n", *server)
	c, err := client.New(*server, cfg)
	if err != nil {
		panic(err)
	}

	// 1. Connect
	ctx := context.Background()
	fmt.Println("1. Connecting...")
	if err := c.Connect(ctx); err != nil {
		panic(err)
	}
	fmt.Printf("   Connected! ShellID: %s\n", c.ShellID())

	// 2. Execute Command
	fmt.Println("2. Executing 'Get-Date'...")
	res, err := c.Execute(ctx, "Get-Date")
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Output: %v\n", strings.TrimSpace(fmt.Sprint(res.Output...)))

	// Save ShellID
	shellID := c.ShellID()

	// 3. Disconnect
	fmt.Println("3. Disconnecting...")
	if err := c.Disconnect(ctx); err != nil {
		panic(err)
	}
	if c.IsConnected() {
		panic("Client reported connected after disconnect!")
	}
	fmt.Println("   Disconnected successfully.")

	// 4. Wait
	fmt.Println("4. Waiting 2 seconds...")
	time.Sleep(2 * time.Second)

	// 5. Reconnect
	fmt.Printf("5. Reconnecting to ShellID: %s...\n", shellID)
	// Create a NEW client instance or reuse?
	// The Reconnect method is on the Client struct.
	// We can reuse the existing 'c' if it supports state reset, or we can create new one.
	// The user request often implies "I lost connection, I make new client and reconnect".
	// Let's try reusing 'c' first as that's what `Reconnect` on `Client` implies.

	if err := c.Reconnect(ctx, shellID); err != nil {
		panic(fmt.Errorf("reconnect failed: %w", err))
	}
	fmt.Println("   Reconnected!")

	// 6. Execute Command again
	fmt.Println("6. Executing 'Get-Date' again...")
	res, err = c.Execute(ctx, "Get-Date")
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Output: %v\n", strings.TrimSpace(fmt.Sprint(res.Output...)))

	// 7. Close
	fmt.Println("7. Closing...")
	if err := c.Close(ctx); err != nil {
		panic(err)
	}
	fmt.Println("Done.")
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
