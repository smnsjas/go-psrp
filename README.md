# go-psrp

<!-- markdownlint-disable MD013 -->
[![Go Reference](https://pkg.go.dev/badge/github.com/smnsjas/go-psrp.svg)](https://pkg.go.dev/github.com/smnsjas/go-psrp)
[![Go Report Card](https://goreportcard.com/badge/github.com/smnsjas/go-psrp)](https://goreportcard.com/report/github.com/smnsjas/go-psrp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
<!-- markdownlint-enable MD013 -->

Complete PowerShell Remoting Protocol implementation for Go with multiple
transport layers.

## Overview

This library builds on [go-psrpcore](https://github.com/smnsjas/go-psrpcore) by
adding transport layers, making it ready for production PowerShell remoting.

<!-- markdownlint-disable MD013 -->
```text
┌─────────────────────────────────────────────────────────┐
│                    Your Application                     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                       go-psrp                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │  client/       High-level convenience API       │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │  powershell/   RunspacePool + Pipeline mgmt     │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │  wsman/        WSMan/WinRM transport            │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │  hvsock/      Hyper-V Socket (PowerShell Direct)│    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                     go-psrpcore                         │
│              (Sans-IO PSRP protocol)                    │
└─────────────────────────────────────────────────────────┘
```
<!-- markdownlint-enable MD013 -->

## Features

- **Multiple Transports**
  - **WSMan/WinRM** - HTTP/HTTPS with SOAP (standard remote PowerShell)
  - **HVSocket** - PowerShell Direct to Hyper-V VMs (Windows only)
- **Authentication**
  - Basic, NTLM (explicit credentials)
    - Supports **Extended Protection (Channel Binding Tokens)** for NTLM
  - Kerberos (pure Go via gokrb5, cross-platform)
  - Windows SSPI (native Negotiate/Kerberos on Windows)
- **Full PSRP Support** - RunspacePools, Pipelines, Output streams
- **Resilient** - Built-in keepalive support (transport-aware) and
  configurable idle timeouts
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

### Concurrent Execution

To execute commands in parallel, configure `MaxRunspaces` > 1:

```go
cfg := client.DefaultConfig()
cfg.MaxRunspaces = 5 // Allow 5 concurrent pipelines

c, _ := client.New(target, cfg)
// ... connect ...

// These will run in parallel (up to 5):
go c.Execute(ctx, "Start-Sleep 5; 'Job 1'")
go c.Execute(ctx, "Start-Sleep 5; 'Job 2'")
```

### Streaming Output

For long-running commands, process output in real-time:

```go
// Returns channels immediately
stream, err := c.ExecuteStream(ctx, "1..10 | ForEach-Object { $_; Start-Sleep 1 }")
if err != nil {
    log.Fatal(err)
}

// Consuming channels (Output, Error, Warning, etc.)
for output := range stream.Output {
    fmt.Println("Received:", output)
}
// Note: ExecuteStream handles cleanup automatically when streams are consumed
```

### Resilience & Reconnection

**Manual Reconnection (WSMan only)**

Disconnect from a session and reconnect later:

```go
// 1. Disconnect (session keeps running on server)
shellID := c.ShellID()
err := c.Disconnect(ctx)

// 2. Reconnect later
c2, _ := client.New(target, cfg)
err := c2.Reconnect(ctx, shellID)
```

**Automatic Reconnection**

Enable automatic reconnection for transient failures (network issues, VM
pause/resume, etc.):

```go
cfg := client.DefaultConfig()
// ... auth settings ...

// Enable auto-reconnect
cfg.Reconnect.Enabled = true

// Optional: Tune retry behavior
cfg.Reconnect.MaxAttempts = 5              // Max retry attempts (0 = infinite)
cfg.Reconnect.InitialDelay = 1 * time.Second  // Delay before first retry
cfg.Reconnect.MaxDelay = 30 * time.Second     // Max delay cap (exponential backoff)
cfg.Reconnect.Jitter = 0.2                    // Randomness factor (0.0-1.0)

c, _ := client.New(target, cfg)
c.Connect(ctx)

// Commands automatically retry on transient failures
result, err := c.Execute(ctx, "Get-Process") // Retries if connection drops mid-command
```

This is especially useful for:

- **HvSocket** (PowerShell Direct) where VM pause/resume breaks connections
- **Unstable networks** with intermittent connectivity
- **Long-running scripts** that need to survive connection hiccups

**Command Retry (Transient Errors)**

Configure retry logic for transient command-level errors (network blips,
timeouts):

```go
// Enable command retry
cfg.Retry = client.DefaultRetryPolicy()
cfg.Retry.MaxAttempts = 3
cfg.Retry.InitialDelay = 100 * time.Millisecond
cfg.Retry.MaxDelay = 5 * time.Second

// IMPORTANT: Only use for idempotent commands!
result, err := c.Execute(ctx, "Get-Process")
```

**Circuit Breaker (Fail Fast)**

Prevent resource exhaustion when the server is down by failing fast:

```go
// Enable circuit breaker
cfg.CircuitBreaker = client.DefaultCircuitBreakerPolicy()
cfg.CircuitBreaker.FailureThreshold = 5      // Open after 5 consecutive failures
cfg.CircuitBreaker.ResetTimeout = 30 * time.Second // Wait 30s before probing
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
cfg.EnableCBT = true // Enable Extended Protection (requires HTTPS)
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

This library enables structured logging (DEBUG, INFO, WARN, ERROR) for both the
client logic and the underlying PSRP protocol.

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
| ---- | ----------- | ------- |
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
| `-cbt` | Enable NTLM Channel Binding Tokens (Extended Protection) | `false` |
| `-auto-reconnect` | Enable automatic reconnection on failures | `false` |

## Package Structure

| Package | Description |
| ------- | ----------- |
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

<!-- markdownlint-disable MD013 -->
- [go-psrpcore](https://github.com/smnsjas/go-psrpcore) - Sans-IO PSRP protocol library
- [pypsrp](https://github.com/jborean93/pypsrp) - Python PSRP client (reference implementation)
<!-- markdownlint-enable MD013 -->

## License

MIT License - see [LICENSE](LICENSE) for details.
