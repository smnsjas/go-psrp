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
- 🔐 **Authentication** - Basic, NTLM (Kerberos planned)
- 📦 **Full PSRP Support** - RunspacePools, Pipelines, Host callbacks
- 🚀 **High-Level API** - Simple one-liner command execution

## Installation

```bash
go get github.com/smnsjas/go-psrp
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/smnsjas/go-psrp/client"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    c, err := client.NewClient(ctx, client.Config{
        Endpoint:   "https://server.domain.com:5986/wsman",
        Username:   "administrator",
        Password:   "password",
        AuthType:   client.AuthNTLM,
        SkipVerify: true, // Only for testing!
    })
    if err != nil {
        log.Fatal(err)
    }
    defer c.Close(ctx)

    result, err := c.Execute(ctx, "Get-Process | Select -First 5 Name, Id")
    if err != nil {
        log.Fatal(err)
    }

    for _, obj := range result.Output {
        fmt.Printf("%+v\n", obj)
    }
}
```

## Package Structure

| Package | Description |
|---------|-------------|
| `wsman` | WSMan/WinRM client, SOAP handling |
| `wsman/auth` | Authentication (Basic, NTLM) |
| `wsman/transport` | HTTP/TLS transport |
| `powershell` | PSRP bridge, RunspacePool, Pipeline |
| `client` | High-level convenience API |

## Related Projects

- [go-psrpcore](https://github.com/smnsjas/go-psrpcore) - Sans-IO PSRP protocol (dependency)
- [pypsrp](https://github.com/jborean93/pypsrp) - Python PSRP client (reference)

## License

MIT License - see [LICENSE](LICENSE) for details.
