// Package client provides a high-level convenience API for PowerShell remoting.
//
// This is the recommended entry point for most users. It handles:
//   - Connection management (WSMan and HvSocket transports)
//   - RunspacePool lifecycle
//   - Automatic reconnection and retry
//   - Simple command execution
//
// # Quick Start
//
//	cfg := client.DefaultConfig()
//	cfg.Username = "administrator"
//	cfg.Password = "password"
//	cfg.UseTLS = true
//
//	c, err := client.New("server.example.com", cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer c.Close(ctx)
//
//	if err := c.Connect(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	result, err := c.Execute(ctx, "Get-Process")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, obj := range result.Output {
//	    fmt.Println(obj)
//	}
package client
