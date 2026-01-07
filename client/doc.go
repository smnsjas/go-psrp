// Package client provides a high-level convenience API for PowerShell remoting.
//
// This is the recommended entry point for most users. It handles:
//   - Connection management
//   - RunspacePool lifecycle
//   - Simple command execution
//
// # Quick Start
//
//	c, err := client.New(ctx, client.Config{
//	    Endpoint: "https://server:5986/wsman",
//	    Username: "administrator",
//	    Password: "password",
//	    AuthType: client.AuthNTLM,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer c.Close(ctx)
//
//	result, err := c.Execute(ctx, "Get-Process")
package client
