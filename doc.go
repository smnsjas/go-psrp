// Package psrp provides a complete PowerShell Remoting Protocol (PSRP) client
// with WinRM/WSMan transport support.
//
// This package builds upon go-psrpcore (the protocol logic) by adding:
//   - WSMan/WinRM transport layer (HTTP/HTTPS with SOAP)
//   - NTLM and Basic authentication
//   - High-level client API for easy PowerShell remoting
//
// # Architecture
//
// The library is organized into layers:
//
//	┌─────────────────────────────────────────────────────────┐
//	│  client/       High-level convenience API               │
//	├─────────────────────────────────────────────────────────┤
//	│  powershell/   RunspacePool + Pipeline management       │
//	├─────────────────────────────────────────────────────────┤
//	│  wsman/        WSMan/WinRM transport layer              │
//	├─────────────────────────────────────────────────────────┤
//	│  go-psrpcore   Sans-IO PSRP protocol (external)         │
//	└─────────────────────────────────────────────────────────┘
//
// # Quick Start
//
//	import "github.com/smnsjas/go-psrp/client"
//
//	// 1. Configure the client
//	cfg := client.DefaultConfig()
//	cfg.Username = "user@domain.com"
//	cfg.Password = "secret"
//	cfg.UseTLS = true
//	cfg.InsecureSkipVerify = true // For testing only
//
//	// 2. Create the client (target is hostname or IP)
//	c, err := client.New("server-hostname", cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// 3. Connect (establishes RunspacePool)
//	ctx := context.Background()
//	if err := c.Connect(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer c.Close(ctx) // Graceful shutdown
//
//	// 4. Execute a command (simple, buffered output)
//	result, err := c.Execute(ctx, "Get-Process | Select -First 5")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Output:", result.Output)
//
// # Concurrency & Multiplexing
//
// The client supports multiplexing multiple commands over a single RunspacePool.
// You can control concurrency limits in the config:
//
//	cfg.MaxRunspaces = 5  // Allow 5 concurrent commands
//	cfg.MaxQueueSize = 100 // Queue up to 100 requests if all slots are busy
//
// # Streaming Output
//
// For long-running scripts or real-time output, use ExecuteStream:
//
//	stream, err := c.ExecuteStream(ctx, "PING.EXE 127.0.0.1 -n 5")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Consume output channels
//	go func() {
//	    for msg := range stream.Output {
//	        fmt.Println("STDOUT:", msg)
//	    }
//	}()
//	go func() {
//	    for err := range stream.Errors {
//	        fmt.Println("STDERR:", err)
//	    }
//	}()
//
//	// Wait for completion
//	if err := stream.Wait(); err != nil {
//	    log.Printf("Command failed: %v", err)
//	}
//
// # Resilience: Reconnect
//
// You can disconnect a session without closing it on the server (saving state),
// and reconnect to it later (even from a new client instance):
//
//	// 1. Disconnect current session
//	shellID := c.ShellID() // Save the ShellID!
//	c.Disconnect(ctx)
//
//	// ... application restart ...
//
//	// 2. Reconnect (using same configuration)
//	c2, _ := client.New("server-hostname", cfg)
//	// Use Reconnect instead of Connect
//	if err := c2.Reconnect(ctx, shellID); err != nil {
//	    log.Fatal("Could not recover session:", err)
//	}
//	// c2 is now connected to the original RunspacePool output
package psrp
