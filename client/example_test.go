package client_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/smnsjas/go-psrp/client"
)

func ExampleNew() {
	// 1. Configure the client
	cfg := client.DefaultConfig()
	cfg.Username = "administrator"
	cfg.Password = "password"
	cfg.UseTLS = true
	cfg.InsecureSkipVerify = false // Production setting

	// 2. Create the client
	c, err := client.New("server.example.com", cfg)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Cleanup on exit
	// Using a new context for cleanup ensures it runs even if the main context is cancelled
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.Close(ctx)
	}()

	// 4. Connect explicitly
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	// 5. Execute commands
	result, err := c.Execute(ctx, "Get-Process | Select-Object -First 1")
	if err != nil {
		log.Fatal(err)
	}

	// 6. Process output
	if result.HadErrors {
		for _, e := range result.Errors {
			fmt.Printf("Error: %v\n", e)
		}
	} else {
		fmt.Printf("Success! Received %d objects\n", len(result.Output))
	}
}

func ExampleClient_Execute_errorHandling() {
	// Demonstrates handling the ErrNotConnected sentinel error
	cfg := client.DefaultConfig()
	cfg.Username = "user"
	cfg.Password = "pass"
	c, err := client.New("server.local", cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	// Forgot to call c.Connect(ctx)!

	_, err = c.Execute(ctx, "Get-Date")
	if errors.Is(err, client.ErrNotConnected) {
		fmt.Println("Caught expected error: Client is not connected")

		// Corrective action: Connect and retry
		// if err := c.Connect(ctx); err != nil { ... }
	}

	// Output: Caught expected error: Client is not connected
}
