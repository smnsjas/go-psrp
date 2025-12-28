//go:build ignore

// This is a manual test script for verifying Kerberos authentication.
// It reads credentials from environment variables and should NEVER be committed with secrets.
//
// Usage:
//   export PSRP_SERVER="server.example.com"
//   export PSRP_USER="username"
//   export PSRP_PASSWORD="password"
//   export PSRP_REALM="EXAMPLE.COM"
//   export KRB5_CONFIG="/path/to/krb5.conf"  # Optional, defaults to /etc/krb5.conf
//   go run kerberos_test_manual.go

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/smnsjas/go-psrp/client"
)

func main() {
	server := os.Getenv("PSRP_SERVER")
	user := os.Getenv("PSRP_USER")
	password := os.Getenv("PSRP_PASSWORD")
	realm := os.Getenv("PSRP_REALM")
	krb5Conf := os.Getenv("KRB5_CONFIG")

	if server == "" || user == "" || password == "" || realm == "" {
		fmt.Println("ERROR: Missing required environment variables.")
		fmt.Println("Required: PSRP_SERVER, PSRP_USER, PSRP_PASSWORD, PSRP_REALM")
		fmt.Println("Optional: KRB5_CONFIG (defaults to /etc/krb5.conf)")
		os.Exit(1)
	}

	fmt.Printf("Connecting to: %s\n", server)
	fmt.Printf("Realm: %s\n", realm)
	fmt.Printf("User: %s\n", user)
	fmt.Printf("krb5.conf: %s\n", krb5Conf)

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
