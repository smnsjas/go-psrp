# go-psrp Project Plan

## Project Overview

**Project Name:** go-psrp  
**Module Path:** `github.com/smnsjas/go-psrp`  
**License:** MIT  
**Go Version:** 1.22+  

### Purpose

Complete PowerShell Remoting Protocol implementation for Go by adding transport layers to go-psrpcore. This project mirrors the relationship between Python's psrpcore (protocol) and pypsrp (transport + protocol).

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                          go-psrp                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  client/          High-level API (convenience methods)  │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  powershell/      RunspacePool + Pipeline management    │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  wsman/           WSMan/WinRM transport layer           │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       go-psrpcore                               │
│         (Sans-IO PSRP protocol - already complete)              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Dependencies

### Required Dependencies

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| `github.com/smnsjas/go-psrpcore` | latest | MIT | Core PSRP protocol |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | UUID generation |
| `github.com/Azure/go-ntlmssp` | latest | MIT | NTLM authentication |

### Standard Library (no external dependency)

- `net/http` - HTTP client
- `crypto/tls` - TLS support
- `encoding/xml` - SOAP/XML handling
- `context` - Context propagation
- `io` - Reader/Writer interfaces

### Future Dependencies (Phase 2+)

| Package | License | Purpose |
|---------|---------|---------|
| `github.com/jcmturner/gokrb5/v8` | Apache 2.0 | Kerberos authentication |
| `github.com/alexbrainman/sspi` | BSD-3-Clause | Windows SSO (optional) |

---

## Project Structure

```
go-psrp/
│
├── go.mod                          # module github.com/smnsjas/go-psrp
├── go.sum
├── LICENSE                         # MIT License
├── README.md                       # Project documentation
├── CONTRIBUTING.md                 # Contribution guidelines
├── doc.go                          # Package-level documentation
├── .gitignore
├── .golangci.yml                   # Linting configuration (match go-psrpcore)
│
├── wsman/                          # WSMan/WinRM transport layer
│   ├── doc.go                      # Package documentation
│   ├── client.go                   # WSMan client - main entry point
│   ├── client_test.go
│   ├── envelope.go                 # SOAP envelope construction
│   ├── envelope_test.go
│   ├── header.go                   # WS-Addressing headers
│   ├── header_test.go
│   ├── namespaces.go               # XML namespace constants
│   ├── operations.go               # Create, Send, Receive, Delete, etc.
│   ├── operations_test.go
│   ├── options.go                  # OptionSet, SelectorSet
│   ├── options_test.go
│   ├── errors.go                   # WSMan fault parsing
│   ├── errors_test.go
│   ├── resource.go                 # Resource URI constants
│   │
│   ├── auth/                       # Authentication handlers
│   │   ├── doc.go
│   │   ├── auth.go                 # Authenticator interface
│   │   ├── basic.go                # Basic authentication
│   │   ├── basic_test.go
│   │   ├── ntlm.go                 # NTLM authentication (Azure/go-ntlmssp)
│   │   ├── ntlm_test.go
│   │   ├── negotiate.go            # SPNEGO/Negotiate (future)
│   │   └── kerberos.go             # Kerberos (future, stub)
│   │
│   └── transport/                  # HTTP transport layer
│       ├── doc.go
│       ├── transport.go            # Transport interface
│       ├── http.go                 # HTTP/HTTPS transport
│       └── http_test.go
│
├── powershell/                     # PSRP over WSMan integration
│   ├── doc.go                      # Package documentation
│   ├── runspacepool.go             # RunspacePool management
│   ├── runspacepool_test.go
│   ├── powershell.go               # PowerShell pipeline execution
│   ├── powershell_test.go
│   ├── streams.go                  # Output stream handling
│   ├── streams_test.go
│   ├── adapter.go                  # io.ReadWriter adapter for WSMan
│   └── adapter_test.go
│
├── client/                         # High-level convenience API
│   ├── doc.go                      # Package documentation
│   ├── client.go                   # Client struct and methods
│   ├── client_test.go
│   ├── options.go                  # Client configuration options
│   ├── copy.go                     # File copy operations (future)
│   └── fetch.go                    # File fetch operations (future)
│
├── internal/                       # Internal utilities (not exported)
│   ├── testutil/                   # Test helpers
│   │   ├── mock_transport.go       # Mock HTTP transport
│   │   └── fixtures.go             # Test fixtures
│   └── xmlutil/                    # XML helpers
│       ├── marshal.go              # Custom XML marshaling
│       └── unmarshal.go            # Custom XML unmarshaling
│
└── cmd/                            # Example applications
    └── psrp-client/                # Example PSRP client
        └── main.go
```

---

## Package Specifications

### Package: `wsman`

**Purpose:** Implement WS-Management protocol for communicating with WinRM endpoints.

**Key Types:**

```go
// Client represents a WSMan client connection
type Client struct {
    endpoint    string
    auth        auth.Authenticator
    httpClient  *http.Client
    maxEnvelope int
    timeout     time.Duration
    locale      string
    dataLocale  string
}

// ClientOption configures a Client
type ClientOption func(*Client)

// Response represents a WSMan response
type Response struct {
    Body    []byte
    Headers map[string]string
}
```

**Key Functions:**

```go
// NewClient creates a new WSMan client
func NewClient(endpoint string, auth auth.Authenticator, opts ...ClientOption) (*Client, error)

// WSMan operations (per MS-WSMV specification)
func (c *Client) Create(ctx context.Context, resourceURI string, body []byte, opts ...RequestOption) (*Response, error)
func (c *Client) Delete(ctx context.Context, resourceURI string, opts ...RequestOption) error
func (c *Client) Command(ctx context.Context, resourceURI string, body []byte, opts ...RequestOption) (*Response, error)
func (c *Client) Send(ctx context.Context, resourceURI string, body []byte, opts ...RequestOption) error
func (c *Client) Receive(ctx context.Context, resourceURI string, opts ...RequestOption) (*Response, error)
func (c *Client) Signal(ctx context.Context, resourceURI string, code SignalCode, opts ...RequestOption) error
```

**Dependencies:** `wsman/auth`, `wsman/transport`

---

### Package: `wsman/auth`

**Purpose:** Authentication handlers for WSMan.

**Key Types:**

```go
// Authenticator handles HTTP authentication
type Authenticator interface {
    // Transport wraps an http.RoundTripper with authentication
    Transport(base http.RoundTripper) http.RoundTripper
    
    // Name returns the authentication scheme name
    Name() string
}

// Credentials holds authentication credentials
type Credentials struct {
    Username string
    Password string
    Domain   string  // Optional, for NTLM
}
```

**Implementations:**

```go
// Basic authentication
func NewBasicAuth(creds Credentials) Authenticator

// NTLM authentication (uses github.com/Azure/go-ntlmssp)
func NewNTLMAuth(creds Credentials) Authenticator
```

---

### Package: `wsman/transport`

**Purpose:** HTTP transport layer abstraction.

**Key Types:**

```go
// Transport handles HTTP communication
type Transport interface {
    Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// HTTPTransport implements Transport over HTTP/HTTPS
type HTTPTransport struct {
    client     *http.Client
    tlsConfig  *tls.Config
}

// HTTPTransportOption configures HTTPTransport
type HTTPTransportOption func(*HTTPTransport)
```

**Key Functions:**

```go
func NewHTTPTransport(opts ...HTTPTransportOption) *HTTPTransport
func WithTLSConfig(cfg *tls.Config) HTTPTransportOption
func WithInsecureSkipVerify(skip bool) HTTPTransportOption
func WithTimeout(d time.Duration) HTTPTransportOption
```

---

### Package: `powershell`

**Purpose:** Bridge WSMan transport to go-psrpcore for PowerShell remoting.

**Key Types:**

```go
// RunspacePool manages a pool of PowerShell runspaces over WSMan
type RunspacePool struct {
    client    *wsman.Client
    shellID   string
    pool      *psrpcore.RunspacePool  // From go-psrpcore
    adapter   *wsmanAdapter
}

// PowerShell represents a PowerShell pipeline
type PowerShell struct {
    pool      *RunspacePool
    pipeline  *psrpcore.Pipeline  // From go-psrpcore
}

// InvocationResult holds pipeline execution results
type InvocationResult struct {
    Output      []interface{}
    Errors      []psrpcore.ErrorRecord
    Warnings    []string
    Verbose     []string
    Debug       []string
    Information []psrpcore.InformationRecord
    Progress    []psrpcore.ProgressRecord
    HadErrors   bool
}
```

**Key Functions:**

```go
// RunspacePool management
func NewRunspacePool(ctx context.Context, client *wsman.Client, opts ...PoolOption) (*RunspacePool, error)
func (rp *RunspacePool) Open(ctx context.Context) error
func (rp *RunspacePool) Close(ctx context.Context) error
func (rp *RunspacePool) CreatePowerShell() *PowerShell

// PowerShell pipeline
func (ps *PowerShell) AddCommand(name string) *PowerShell
func (ps *PowerShell) AddScript(script string) *PowerShell
func (ps *PowerShell) AddParameter(name string, value interface{}) *PowerShell
func (ps *PowerShell) Invoke(ctx context.Context) (*InvocationResult, error)
func (ps *PowerShell) InvokeAsync(ctx context.Context) (<-chan *InvocationResult, error)
func (ps *PowerShell) Stop(ctx context.Context) error
```

---

### Package: `client`

**Purpose:** High-level convenience API for common operations.

**Key Types:**

```go
// Client provides a high-level interface for PowerShell remoting
type Client struct {
    wsmanClient *wsman.Client
    pool        *powershell.RunspacePool
}

// Config holds client configuration
type Config struct {
    Endpoint    string            // e.g., "https://server:5986/wsman"
    Username    string
    Password    string
    Domain      string            // Optional
    AuthType    AuthType          // Basic, NTLM, Kerberos
    TLSConfig   *tls.Config       // Optional
    SkipVerify  bool              // Skip TLS verification
    Timeout     time.Duration
}
```

**Key Functions:**

```go
func NewClient(ctx context.Context, cfg Config) (*Client, error)
func (c *Client) Close(ctx context.Context) error
func (c *Client) Execute(ctx context.Context, script string) (*powershell.InvocationResult, error)
func (c *Client) ExecuteCommand(ctx context.Context, command string, args ...string) (*powershell.InvocationResult, error)

// Convenience methods (future)
func (c *Client) CopyFile(ctx context.Context, localPath, remotePath string) error
func (c *Client) FetchFile(ctx context.Context, remotePath, localPath string) error
```

---

## Development Phases

### Phase 1: Core WSMan Transport (Weeks 1-2)

**Goal:** Establish basic WSMan communication over HTTPS with NTLM auth.

**Tasks:**

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| 1.1 | Project scaffolding (go.mod, structure, docs) | 2 | P0 |
| 1.2 | XML namespace constants | 1 | P0 |
| 1.3 | SOAP envelope builder | 8 | P0 |
| 1.4 | WS-Addressing header construction | 4 | P0 |
| 1.5 | HTTP transport with TLS | 4 | P0 |
| 1.6 | Basic authentication | 2 | P0 |
| 1.7 | NTLM authentication (Azure/go-ntlmssp) | 4 | P0 |
| 1.8 | WSMan operations (Create, Delete, Send, Receive, Signal) | 12 | P0 |
| 1.9 | WSMan fault/error parsing | 4 | P0 |
| 1.10 | Unit tests for all above | 8 | P0 |

**Deliverable:** Working WSMan client that can make authenticated requests.

**Test Criteria:**
- [ ] Can establish HTTPS connection to WinRM endpoint
- [ ] NTLM authentication succeeds
- [ ] Can send SOAP request and receive response
- [ ] Proper error handling for faults

---

### Phase 2: WSMan ↔ psrpcore Bridge (Weeks 3-4)

**Goal:** Connect WSMan transport to go-psrpcore for PSRP communication.

**Tasks:**

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| 2.1 | PSRP resource URI constants | 1 | P0 |
| 2.2 | io.ReadWriter adapter for WSMan Send/Receive | 8 | P0 |
| 2.3 | RunspacePool wrapper | 8 | P0 |
| 2.4 | PowerShell pipeline wrapper | 6 | P0 |
| 2.5 | Output stream handling | 6 | P0 |
| 2.6 | Error/Warning/Verbose stream handling | 4 | P0 |
| 2.7 | Progress record handling | 2 | P1 |
| 2.8 | Integration tests with real WinRM | 8 | P0 |
| 2.9 | Unit tests with mock transport | 6 | P0 |

**Deliverable:** Can execute PowerShell commands via WinRM.

**Test Criteria:**
- [ ] Can create RunspacePool over WSMan
- [ ] Can execute simple script (e.g., `Get-Process | Select -First 1`)
- [ ] Receives typed output objects
- [ ] Properly closes runspace

---

### Phase 3: High-Level Client API (Week 5)

**Goal:** Provide convenient, user-friendly API.

**Tasks:**

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| 3.1 | Client configuration struct | 2 | P0 |
| 3.2 | Client constructor with sensible defaults | 4 | P0 |
| 3.3 | Execute() convenience method | 2 | P0 |
| 3.4 | ExecuteCommand() with argument handling | 4 | P0 |
| 3.5 | Connection pooling/reuse | 4 | P1 |
| 3.6 | Example application (cmd/psrp-client) | 4 | P0 |
| 3.7 | Documentation and examples | 4 | P0 |

**Deliverable:** Easy-to-use client for common operations.

**Test Criteria:**
- [ ] Simple one-liner to connect and execute
- [ ] Example application works
- [ ] GoDoc documentation complete

---

### Phase 4: Polish & Testing (Week 6)

**Goal:** Production-ready quality.

**Tasks:**

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| 4.1 | golangci-lint compliance | 4 | P0 |
| 4.2 | Edge case testing | 8 | P0 |
| 4.3 | Timeout/cancellation testing | 4 | P0 |
| 4.4 | Large output handling | 4 | P0 |
| 4.5 | Error message improvements | 2 | P1 |
| 4.6 | README and CONTRIBUTING | 4 | P0 |
| 4.7 | CI/CD setup (GitHub Actions) | 4 | P1 |

**Deliverable:** Release-ready v0.1.0.

---

### Future Phases (Post v0.1.0)

| Phase | Feature | Priority |
|-------|---------|----------|
| 5 | Kerberos authentication (gokrb5) | P1 |
| 6 | Windows SSPI integration (alexbrainman/sspi) | P2 |
| 7 | File copy/fetch operations | P2 |
| 8 | SSH transport (PowerShell Core) | P2 |
| 9 | VMBus transport integration | P2 |
| 10 | Connection multiplexing | P3 |

---

## Technical Specifications

### SOAP Envelope Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
    <s:Header>
        <a:To>https://server:5986/wsman</a:To>
        <a:ReplyTo>
            <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
        </a:ReplyTo>
        <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
        <a:MessageID>uuid:...</a:MessageID>
        <w:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.PowerShell</w:ResourceURI>
        <w:MaxEnvelopeSize>153600</w:MaxEnvelopeSize>
        <w:OperationTimeout>PT60S</w:OperationTimeout>
        <p:DataLocale xml:lang="en-US"/>
        <p:Locale xml:lang="en-US"/>
    </s:Header>
    <s:Body>
        <!-- Operation-specific content -->
    </s:Body>
</s:Envelope>
```

### WSMan Operations for PSRP

| WSMan Action | PSRP Use |
|--------------|----------|
| Create | Create RunspacePool shell |
| Command | Create Pipeline |
| Send | Send PSRP fragments (stdin stream) |
| Receive | Receive PSRP fragments (stdout/stderr) |
| Signal | Terminate pipeline or close shell |
| Delete | Close RunspacePool shell |

### PSRP Fragment Wrapping

```xml
<rsp:Send>
    <rsp:Stream Name="stdin" CommandId="...">
        <!-- Base64-encoded PSRP fragment from go-psrpcore -->
    </rsp:Stream>
</rsp:Send>
```

### io.ReadWriter Adapter Pattern

```go
// wsmanAdapter bridges WSMan and go-psrpcore's io.ReadWriter interface
type wsmanAdapter struct {
    client    *wsman.Client
    shellID   string
    commandID string
    buffer    bytes.Buffer
}

func (a *wsmanAdapter) Read(p []byte) (n int, err error) {
    // If buffer empty, call WSMan Receive
    // Extract PSRP fragments from <rsp:Stream> elements
    // Base64 decode and return to go-psrpcore
}

func (a *wsmanAdapter) Write(p []byte) (n int, err error) {
    // Base64 encode PSRP fragment
    // Wrap in <rsp:Stream> element
    // Call WSMan Send
}
```

---

## Configuration Reference

### Environment Variables (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `PSRP_ENDPOINT` | WinRM endpoint URL | - |
| `PSRP_USERNAME` | Username | - |
| `PSRP_PASSWORD` | Password | - |
| `PSRP_SKIP_VERIFY` | Skip TLS verification | `false` |
| `PSRP_TIMEOUT` | Operation timeout | `60s` |

### Client Configuration

```go
cfg := client.Config{
    Endpoint:   "https://server.domain.com:5986/wsman",
    Username:   "administrator",
    Password:   "password",
    Domain:     "DOMAIN",           // Optional for NTLM
    AuthType:   client.AuthNTLM,    // Basic, NTLM, Kerberos
    SkipVerify: false,              // Don't skip in production!
    Timeout:    60 * time.Second,
    TLSConfig:  nil,                // Use custom *tls.Config if needed
}
```

---

## Testing Strategy

### Unit Tests

- Located alongside source files (`*_test.go`)
- Table-driven tests where applicable
- Mock HTTP transport for WSMan tests
- Mock RunspacePool for powershell tests

### Integration Tests

- Requires live WinRM endpoint
- Controlled via build tag: `//go:build integration`
- Run with: `go test -tags=integration ./...`

### Test Fixtures

Located in `internal/testutil/`:
- SOAP response samples
- PSRP message samples
- Error response samples

---

## Code Style Guidelines

Following go-psrpcore conventions:

### File Organization

- One primary type per file (e.g., `client.go` contains `Client`)
- Related helper types can be in same file
- Tests in `*_test.go` alongside source

### Naming

- Exported types: `PascalCase` with doc comments
- Unexported types: `camelCase`
- Interfaces: verb-er pattern (`Authenticator`, `Transport`)
- Options: `WithXxx` pattern for functional options

### Documentation

- All exported types and functions have doc comments
- Package-level documentation in `doc.go`
- Examples in `example_test.go` where helpful

### Error Handling

```go
// Define package errors
var (
    ErrNotConnected = errors.New("wsman: not connected")
    ErrAuthFailed   = errors.New("wsman: authentication failed")
)

// Wrap errors with context
return fmt.Errorf("wsman: failed to create shell: %w", err)
```

### Context Usage

- All blocking operations accept `context.Context`
- Honor cancellation and deadlines
- Use `ctx` as first parameter

---

## Success Criteria for v0.1.0

- [ ] Execute PowerShell scripts on remote Windows servers via WinRM/HTTPS
- [ ] NTLM authentication working
- [ ] Proper output stream handling (Output, Error, Warning, Verbose, Debug)
- [ ] Graceful error handling with meaningful messages
- [ ] golangci-lint passes with go-psrpcore configuration
- [ ] Test coverage > 70%
- [ ] Documentation complete (README, GoDoc, examples)
- [ ] Example application functional

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| NTLM edge cases | Medium | Medium | Test against multiple Windows versions |
| Large message handling | Medium | Medium | Test with large scripts/output |
| TLS compatibility | Low | High | Support custom TLS config |
| Timeout handling | Medium | Medium | Comprehensive timeout tests |
| Azure/go-ntlmssp issues | Low | High | Library is mature and widely used |

---

## References

### Specifications

- [MS-PSRP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/) - PowerShell Remoting Protocol
- [MS-WSMV](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/) - WS-Management Extensions for Windows
- [DMTF DSP0226](https://www.dmtf.org/standards/wsman) - WS-Management Specification

### Reference Implementations

- [psrpcore](https://github.com/jborean93/psrpcore) - Python PSRP protocol
- [pypsrp](https://github.com/jborean93/pypsrp) - Python PSRP client with WSMan
- [go-psrpcore](https://github.com/smnsjas/go-psrpcore) - Go PSRP protocol (this project's foundation)

### Dependencies

- [Azure/go-ntlmssp](https://github.com/Azure/go-ntlmssp) - NTLM authentication
- [google/uuid](https://github.com/google/uuid) - UUID generation

---

## Appendix A: Sample go.mod

```go
module github.com/smnsjas/go-psrp

go 1.22

require (
    github.com/smnsjas/go-psrpcore v0.1.0
    github.com/google/uuid v1.6.0
    github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358
)
```

---

## Appendix B: Sample Usage

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

    // Create client
    c, err := client.NewClient(ctx, client.Config{
        Endpoint:   "https://myserver.domain.com:5986/wsman",
        Username:   "administrator",
        Password:   "MySecurePassword",
        AuthType:   client.AuthNTLM,
        SkipVerify: true, // Only for testing!
    })
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer c.Close(ctx)

    // Execute script
    result, err := c.Execute(ctx, `
        Get-Process | 
        Sort-Object -Property CPU -Descending | 
        Select-Object -First 5 Name, Id, CPU
    `)
    if err != nil {
        log.Fatalf("Execution failed: %v", err)
    }

    // Print output
    for _, obj := range result.Output {
        fmt.Printf("%+v\n", obj)
    }

    if result.HadErrors {
        for _, e := range result.Errors {
            fmt.Printf("Error: %s\n", e.Message)
        }
    }
}
```

---

## Appendix C: golangci.yml (Match go-psrpcore)

```yaml
linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gofmt
    - goimports
    - misspell
    - unconvert
    - gocritic

linters-settings:
  gocritic:
    enabled-tags:
      - diagnostic
      - style
      - performance

issues:
  exclude-use-default: false
```

---

*Document Version: 1.0*  
*Created: December 2024*  
*Author: Jason / Claude*
