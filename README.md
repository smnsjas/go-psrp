# go-psrp

[![Go Reference](https://pkg.go.dev/badge/github.com/smnsjas/go-psrp.svg)](https://pkg.go.dev/github.com/smnsjas/go-psrp)
[![Go Report Card](https://goreportcard.com/badge/github.com/smnsjas/go-psrp)](https://goreportcard.com/report/github.com/smnsjas/go-psrp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Complete PowerShell Remoting Protocol implementation for Go with multiple transport layers.

## Overview

This library builds on [go-psrpcore](https://github.com/smnsjas/go-psrpcore) by adding transport layers, making it ready for production PowerShell remoting.

```
┌─────────────────────────────────────────────────────────┐
│                    Your Application                     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                       go-psrp                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │  client/       High-level convenience API       │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  powershell/   RunspacePool + Pipeline mgmt     │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  wsman/        WSMan/WinRM transport            │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  hvsock/       Hyper-V Socket (PowerShell Direct)│   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                     go-psrpcore                         │
│              (Sans-IO PSRP protocol)                    │
└─────────────────────────────────────────────────────────┘
```

## Features

- **Multiple Transports**
  - **WSMan/WinRM** - HTTP/HTTPS with SOAP (standard remote PowerShell)
  - **HVSocket** - PowerShell Direct to Hyper-V VMs (Windows only)
- **Authentication**
  - Basic, NTLM (explicit credentials)
  - Kerberos (pure Go via gokrb5, cross-platform)
  - Windows SSPI (native Negotiate/Kerberos on Windows)
- **Full PSRP Support** - RunspacePools, Pipelines, Output streams
- **Resilient** - Built-in keepalive support (transport-aware) and configurable idle timeouts
- **High-Level API** - Simple command execution
- **Secure** - TLS 1.2+ by default, pure Go implementation

## Installation

```bash
go get github.com/smnsjas/go-psrp
```

## Quick Start

### Basic Usage (WSMan)

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/smnsjas/go-psrp/client"
)

func main() {
    // Configure the client
    cfg := client.DefaultConfig()
    cfg.Username = "administrator"
    cfg.Password = "password"
    cfg.UseTLS = true
    cfg.Port = 5986
    cfg.InsecureSkipVerify = true // Only for testing!

    // Create the client
    c, err := client.New("server.domain.com", cfg)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Connect to the server
    if err := c.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer c.Close(ctx)

    // Execute a PowerShell command
    result, err := c.Execute(ctx, "Get-Process | Select-Object -First 5 Name, Id")
    if err != nil {
        log.Fatal(err)
    }

    for _, obj := range result.Output {
        fmt.Printf("%+v\n", obj)
    }
}
```

### PowerShell Direct (HVSocket) - Windows Only

Connect directly to a Hyper-V VM without network configuration:

```go
cfg := client.DefaultConfig()
cfg.Transport = client.TransportHvSocket
cfg.VMID = "12345678-1234-1234-1234-123456789abc" // VM GUID
cfg.Username = "administrator"
cfg.Password = "vmpassword"
cfg.Domain = "."  // "." for local accounts

c, err := client.New("", cfg)  // Server not needed for HVSocket
```

### Using NTLM Authentication

```go
cfg := client.DefaultConfig()
cfg.Username = "DOMAIN\\user"  // Note: DOMAIN\user format
cfg.Password = "password"
cfg.AuthType = client.AuthNTLM
cfg.UseTLS = true
cfg.Port = 5986
```

### Using Kerberos Authentication (Cross-Platform)

```go
cfg := client.DefaultConfig()
cfg.Username = "user"
cfg.Password = "password"
cfg.AuthType = client.AuthKerberos
cfg.Realm = "WIN.DOMAIN.COM"
cfg.Krb5ConfPath = "/etc/krb5.conf"
cfg.UseTLS = true
cfg.Port = 5986
```

With pre-existing Kerberos tickets (`kinit`):

```go
cfg := client.DefaultConfig()
cfg.AuthType = client.AuthKerberos
cfg.Realm = "WIN.DOMAIN.COM"
cfg.CCachePath = "/tmp/krb5cc_1000" // Or use KRB5CCNAME env var
cfg.UseTLS = true
```

### Windows SSPI (Native Negotiate)

On Windows, the client can use the system's Negotiate provider:

```go
cfg := client.DefaultConfig()
cfg.Username = "DOMAIN\\user"
cfg.Password = "password"
cfg.AuthType = client.AuthNegotiate  // Uses Windows SSPI on Windows
cfg.UseTLS = true
```

### Keepalive & Timeouts

Configure session timeouts and keepalive mechanism:

```go
cfg := client.DefaultConfig()
// ... auth settings ...

// How often to send PSRP keepalive messages (default: 0/disabled)
// Recommended for long-running scripts on HvSocket or unstable networks.
// (For WSMan, this is disabled as it uses protocol-level keepalives)
cfg.KeepAliveInterval = 30 * time.Second

// WSMan Shell Idle Timeout (ISO8601 duration string)
// Defaults to "PT30M" (30 minutes) if unset.
// Example: Set to 1 hour
cfg.IdleTimeout = "PT1H"
```

## Logging

 This library enables structured logging (DEBUG, INFO, WARN, ERROR) for both the client logic and the underlying PSRP protocol.

### Environment Variables

 Global logging can be enabled setting the `PSRP_LOG_LEVEL` environment variable:

 ```bash
 export PSRP_LOG_LEVEL=info  # options: debug, info, warn, error
 ```

### Custom Logger

 You can inject your own `slog.Logger` into the client:

 ```go
 // Create a JSON logger
 logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
     Level: slog.LevelInfo,
 }))
 
 // Inject it into the client
 client.SetSlogLogger(logger)
 ```

## CLI Tool

A command-line tool is included for testing and quick scripts:

```bash
# Build the CLI
go build ./cmd/psrp-client

# WSMan with NTLM
./psrp-client -server myserver -user "DOMAIN\\admin" -tls -ntlm \
    -script "Get-Process | Select-Object -First 5"

# WSMan with Kerberos (using credential cache)
./psrp-client -server myserver -user testuser -realm WIN.DOMAIN.COM \
    -ccache /tmp/krb5cc_501 -tls -insecure \
    -script "Get-Service"

# PowerShell Direct (HVSocket) - Windows only
./psrp-client -hvsocket -vmid "12345678-..." -user admin -domain "." \
    -script "Get-Process"
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | WinRM server hostname | (required for WSMan) |
| `-user` | Username | (required) |
| `-pass` | Password (or use `PSRP_PASSWORD` env) | - |
| `-script` | PowerShell script to execute | `Get-Process` |
| `-tls` | Use HTTPS | `false` |
| `-port` | WinRM port | 5985/5986 |
| `-ntlm` | Use NTLM auth | `false` |
| `-kerberos` | Use Kerberos auth | `false` |
| `-realm` | Kerberos realm | - |
| `-krb5conf` | Path to krb5.conf | `/etc/krb5.conf` |
| `-ccache` | Kerberos credential cache | `$KRB5CCNAME` |
| `-insecure` | Skip TLS verification | `false` |
| `-timeout` | Operation timeout | `60s` |
| `-hvsocket` | Use HVSocket transport | `false` |
| `-vmid` | VM GUID for HVSocket | - |
| `-domain` | Domain for HVSocket auth | `.` |
| `-configname` | PowerShell configuration name | - |
| `-loglevel` | Log level (`debug`, `info`, `warn`, `error`) | - |
| `-keepalive` | PSRP Keepalive interval (e.g., `30s`) | `0` (disabled) |
| `-idle-timeout` | WSMan Shell idle timeout (ISO8601, e.g. `PT1H`) | `PT30M` |
| `-list-sessions` | List disconnected sessions on server | `false` |
| `-cleanup` | Cleanup (remove) disconnected sessions | `false` |
| `-recover` | Recover output from pipeline with CommandID | - |
| `-async` | Start command and disconnect immediately | `false` |
| `-save-session` | Save session state to file on disconnect | - |
| `-restore-session` | Restore session state from file | - |

## Package Structure

| Package | Description |
|---------|-------------|
| `client` | High-level API: `New()`, `Connect()`, `Execute()`, `Close()` |
| `powershell` | PSRP bridge, `WSManBackend`, `HvSocketBackend` |
| `wsman` | WSMan client, SOAP envelope builder, operations |
| `wsman/auth` | Authentication: `BasicAuth`, `NTLMAuth`, `NegotiateAuth`, `PureKerberosProvider` |
| `wsman/transport` | HTTP/TLS transport layer |
| `hvsock` | Hyper-V Socket connectivity (Windows only) |

## Configuration

### WinRM Server Setup

On the target Windows server, enable WinRM:

```powershell
# Enable WinRM (run as Administrator)
Enable-PSRemoting -Force

# For HTTPS, create and configure a certificate
# (Required for production)

# For testing with HTTP (not recommended for production)
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
```

### Firewall

Ensure these ports are open:

- **5985** - HTTP
- **5986** - HTTPS

## Error Handling

```go
result, err := c.Execute(ctx, "Get-Process -Name nonexistent")
if err != nil {
    // Connection or protocol error
    log.Fatal(err)
}

if result.HadErrors {
    // PowerShell errors (non-terminating)
    for _, e := range result.Errors {
        fmt.Printf("PowerShell Error: %v\n", e)
    }
}
```

## Related Projects

- [go-psrpcore](https://github.com/smnsjas/go-psrpcore) - Sans-IO PSRP protocol library
- [pypsrp](https://github.com/jborean93/pypsrp) - Python PSRP client (reference implementation)

## License

MIT License - see [LICENSE](LICENSE) for details.
