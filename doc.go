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
//	cfg := client.Config{
//	    Endpoint: "https://server:5986/wsman",
//	    Username: "administrator",
//	    Password: "password",
//	    AuthType: client.AuthNTLM,
//	}
//	c, err := client.NewClient(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer c.Close(ctx)
//
//	result, err := c.Execute(ctx, "Get-Process | Select -First 5")
package psrp
