# go-psrp

[![Go Reference](https://pkg.go.dev/badge/github.com/smnsjas/go-psrp.svg)](https://pkg.go.dev/github.com/smnsjas/go-psrp)
[![Go Report Card](https://goreportcard.com/badge/github.com/smnsjas/go-psrp)](https://goreportcard.com/report/github.com/smnsjas/go-psrp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Complete PowerShell Remoting Protocol implementation for Go with WSMan/WinRM transport.

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
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                     go-psrpcore                         │
│              (Sans-IO PSRP protocol)                    │
└─────────────────────────────────────────────────────────┘
```

## Features

- 🔌 **WSMan/WinRM Transport** - HTTP/HTTPS with SOAP
- 🔐 **Authentication** - Basic, NTLM, and Kerberos (Active Directory)
- 📦 **Full PSRP Support** - RunspacePools, Pipelines, Output streams
- 🚀 **High-Level API** - Simple command execution
- 🛡️ **Secure** - TLS 1.2+ by default, pure Go implementation

## Installation

```bash
go get github.com/smnsjas/go-psrp
```

## Quick Start

### Basic Usage

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

    fmt.Printf("Output: %s\n", string(result.Output))
    if result.HadErrors {
        fmt.Printf("Errors: %s\n", string(result.Errors))
    }
}
```

### Using NTLM Authentication

```go
cfg := client.DefaultConfig()
cfg.Username = "domain\\user"
cfg.Password = "password"
cfg.AuthType = client.AuthNTLM
```

### Using Kerberos Authentication (Active Directory)

```go
cfg := client.DefaultConfig()
cfg.Username = "user@REALM"
cfg.Password = "password"
cfg.AuthType = client.AuthKerberos
cfg.Realm = "WIN.DOMAIN.COM"
cfg.Krb5ConfPath = "/etc/krb5.conf" // Optional, defaults to /etc/krb5.conf
cfg.UseTLS = true
cfg.Port = 5986
```

For SSO (using pre-existing Kerberos tickets from `kinit`):

```go
cfg := client.DefaultConfig()
cfg.Username = "user@REALM"
cfg.AuthType = client.AuthKerberos
cfg.Realm = "WIN.DOMAIN.COM"
cfg.CCachePath = "/tmp/krb5cc_1000" // Or set KRB5CCNAME env var
cfg.UseTLS = true
```

### HTTP (Non-TLS) Connection

```go
cfg := client.DefaultConfig()
cfg.Username = "administrator"
cfg.Password = "password"
cfg.UseTLS = false
cfg.Port = 5985 // Default HTTP port
```

## CLI Tool

A command-line tool is included for testing and quick scripts:

```bash
# Build the CLI
go build ./cmd/psrp-client

# Run a command
./psrp-client -server myserver -user admin -pass secret \
    -script "Get-Process | Select-Object -First 5"

# With HTTPS and NTLM
./psrp-client -server myserver -user domain\\admin -pass secret \
    -tls -ntlm -script "Get-Service"
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | WinRM server hostname | (required) |
| `-user` | Username | (required) |
| `-pass` | Password | (required unless using ccache) |
| `-script` | PowerShell script to execute | `Get-Process` |
| `-tls` | Use HTTPS | `false` |
| `-port` | WinRM port | 5985 (HTTP), 5986 (HTTPS) |
| `-ntlm` | Use NTLM auth | `false` (Basic) |
| `-kerberos` | Use Kerberos auth | `false` |
| `-realm` | Kerberos realm (e.g., WIN.DOMAIN.COM) | (auto-detect) |
| `-krb5conf` | Path to krb5.conf | `/etc/krb5.conf` |
| `-ccache` | Path to Kerberos credential cache | `$KRB5CCNAME` |
| `-insecure` | Skip TLS verification | `false` |
| `-timeout` | Operation timeout | `60s` |

## Package Structure

| Package | Description |
|---------|-------------|
| `client` | High-level API: `New()`, `Connect()`, `Execute()`, `Close()` |
| `powershell` | PSRP bridge, `RunspacePool`, `Pipeline`, `WSManTransport` |
| `wsman` | WSMan client, SOAP envelope builder, operations |
| `wsman/auth` | Authentication: `BasicAuth`, `NTLMAuth`, `NegotiateAuth` (Kerberos) |
| `wsman/transport` | HTTP/TLS transport layer |

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
    fmt.Printf("PowerShell Error: %s\n", string(result.Errors))
}
```

## Related Projects

- [go-psrpcore](https://github.com/smnsjas/go-psrpcore) - Sans-IO PSRP protocol library
- [pypsrp](https://github.com/jborean93/pypsrp) - Python PSRP client (reference implementation)

## License

MIT License - see [LICENSE](LICENSE) for details.
