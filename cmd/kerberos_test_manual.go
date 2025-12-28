//go:build ignore

// This is a manual test script for verifying Kerberos authentication.
// It reads credentials from environment variables and should NEVER be committed with secrets.
//
// Usage:
//   export PSRP_SERVER="server.example.com"
//   export PSRP_USER="username"
//   export PSRP_REALM="EXAMPLE.COM"
//   export KRB5_CONFIG="/path/to/krb5.conf"  # Optional, defaults to /etc/krb5.conf
//   export SSPI_RS_LIB="/path/to/libsspi.dylib"  # For sspi-rs backend
//   go run kerberos_test_manual.go
//
// Password will be prompted securely (hidden input).

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"golang.org/x/term"
)

func main() {
	server := os.Getenv("PSRP_SERVER")
	user := os.Getenv("PSRP_USER")
	realm := os.Getenv("PSRP_REALM")
	krb5Conf := os.Getenv("KRB5_CONFIG")

	if server == "" || user == "" || realm == "" {
		fmt.Println("ERROR: Missing required environment variables.")
		fmt.Println("Required: PSRP_SERVER, PSRP_USER, PSRP_REALM")
		fmt.Println("Optional: KRB5_CONFIG, SSPI_RS_LIB")
		os.Exit(1)
	}

	// Check for password in env (for CI) or prompt securely
	password := os.Getenv("PSRP_PASSWORD")
	if password == "" {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // newline after password
		if err != nil {
			fmt.Printf("ERROR reading password: %v\n", err)
			os.Exit(1)
		}
		password = string(passwordBytes)
	}

	fmt.Printf("Connecting to: %s\n", server)
	fmt.Printf("Realm: %s\n", realm)
	fmt.Printf("User: %s\n", user)
	if krb5Conf != "" {
		fmt.Printf("krb5.conf: %s\n", krb5Conf)
	}
	if lib := os.Getenv("SSPI_RS_LIB"); lib != "" {
		fmt.Printf("sspi-rs lib: %s\n", lib)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := client.Config{
		Port:         5985,
		UseTLS:       false,
		Timeout:      60 * time.Second,
		AuthType:     client.AuthKerberos,
		Username:     user,
		Password:     password,
		Realm:        realm,
		Krb5ConfPath: krb5Conf,
	}

	c, err := client.New(server, cfg)
	if err != nil {
		fmt.Printf("ERROR creating client: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Connecting...")
	if err := c.Connect(ctx); err != nil {
		fmt.Printf("ERROR connecting: %v\n", err)
		os.Exit(1)
	}
	defer c.Close(ctx)

	fmt.Println("Connected! Executing test command...")

	result, err := c.Execute(ctx, `Write-Output "Kerberos auth successful! Running as: $env:USERNAME"`)
	if err != nil {
		fmt.Printf("ERROR executing: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n--- OUTPUT ---")
	for _, o := range result.Output {
		fmt.Println(o)
	}

	if result.HadErrors {
		fmt.Println("\n--- ERRORS ---")
		for _, e := range result.Errors {
			fmt.Println(e)
		}
	}

	fmt.Println("\n✅ Kerberos authentication verified successfully!")
}
