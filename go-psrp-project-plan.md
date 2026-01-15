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

### Implementation Status (As of Jan 2026)

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Core WSMan Transport | ✅ **Completed** |
| **2** | WSMan ↔ psrpcore Bridge | ✅ **Completed** |
| **3** | High-Level Client API | ✅ **Completed** |
| **4** | Polish & Testing | 🚧 **In Progress** (CI/CD pending) |
| **4.5** | Security & Optimization | ✅ **Completed** |

### Phase 1: Core WSMan Transport (Completed)

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
| 10 | **Multiplexing & Resilience** | **See dedicated section below** |

---

## Multiplexing & Resilience Implementation

### Overview

This section covers shell reuse (multiplexing) and connection resilience features that transform go-psrp from a basic client into a production-ready automation library.

**Goals:**

- Reduce command latency from 1-2s to <100ms via shell reuse
- Support concurrent pipeline execution
- Handle disconnects gracefully with configurable recovery
- Enable resumption of long-running tasks after network failures

```
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE DEPENDENCIES                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                    ┌─────────────────────┐                       │
│                    │     FOUNDATION      │                       │
│                    │  (Required by both) │                       │
│                    ├─────────────────────┤                       │
│                    │ • Dispatch loop fix │                       │
│                    │ • Connection state  │                       │
│                    │ • Keep-alive        │                       │
│                    │ • Graceful shutdown │                       │
│                    └──────────┬──────────┘                       │
│                               │                                  │
│              ┌────────────────┼────────────────┐                 │
│              ▼                                 ▼                 │
│   ┌──────────────────┐              ┌──────────────────┐         │
│   │   MULTIPLEXING   │              │    RESILIENCE    │         │
│   ├──────────────────┤              ├──────────────────┤         │
│   │ • Shell reuse    │              │ • Auto-reconnect │         │
│   │ • ExecuteAsync() │              │ • WSMan Disc/Rec │         │
│   │ • ExecuteStream()│              │ • Session store  │         │
│   │ • Pool config    │              │ • Resume results │         │
│   └──────────────────┘              └──────────────────┘         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture Review: What's Already Implemented

Before implementation, we reviewed go-psrpcore against expert critique (Gemini). Most concurrency features are already present:

| Feature | Location | Status |
|---------|----------|--------|
| Dispatch routing by PipelineID | `runspace.go:dispatchLoop()` | ✅ Complete |
| Pipeline streaming | `pipeline.go` | ✅ 7 buffered channels, back-pressure |
| PSRP Stop message | `pipeline.go:Stop()` | ✅ Sends SIGNAL, waits for Stopped |
| RunspacePool XML config | `runspace.go:createInitRunspacePoolMessage()` | ✅ Min/Max runspaces |
| Thread-safe pipelines | `pipeline.go` | ✅ `sync.RWMutex` + context cancellation |
| Back-pressure handling | `pipeline.go:HandleMessage()` | ✅ 5s timeout on channel sends |

### Critical Bug: StartDispatchLoop()

**Location:** `/Users/jasonsimons/Projects/go-psrp/client/client.go:Execute()`

**Bug:** `StartDispatchLoop()` is called every time Execute() runs instead of once at Connect().

```go
// Current (WRONG)
func (c *Client) Execute(ctx context.Context, script string) (*Result, error) {
    // ...
    psrpPool.StartDispatchLoop()  // Called every execution!
    // ...
}

// Fixed
func (c *Client) Connect(ctx context.Context) error {
    // ... existing connection logic ...
    c.psrpPool.StartDispatchLoop()  // Called once
    return nil
}
```

### Implementation Phases

#### Phase M1: Foundation (Week 1-2)

**Goal:** Fix critical bugs, establish connection lifecycle management.

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| M1.1 | Fix `StartDispatchLoop()` bug - move to Connect() | 2 | P0 |
| M1.2 | Add pool state tracking (`poolReady`, `poolClosed` flags) | 4 | P0 |
| M1.3 | Implement connection state machine | 6 | P0 |
| M1.4 | Implement keep-alive heartbeat mechanism | 8 | P0 |
| M1.5 | Graceful shutdown with active pipelines | 6 | P0 |
| M1.6 | Test: 1000 sequential Execute() with single Connect/Close | 4 | P0 |
| M1.7 | **Client-side semaphore tied to MaxRunspaces** | 6 | P0 |
| M1.8 | **Pool health states (Healthy/Degraded/Unhealthy)** | 4 | P0 |
| M1.9 | **Atomic CI (Call ID) counter + pending request table** | 4 | P1 |

**Keep-Alive Design:**

> **Important Distinction (per Gemini review):**
>
> - **Keep-Alive** = Prevention - stops server from killing idle sessions
> - **Auto-Reconnect** = Recovery - handles actual network failures (Phase M3)
>
> These are separate concerns. Keep-alive prevents timeout; it doesn't recover from dropped connections.

```go
// client/keepalive.go
const DefaultKeepAliveInterval = 30 * time.Second

type keepAlive struct {
    interval     time.Duration
    ticker       *time.Ticker
    done         chan struct{}
    client       *Client
    lastActivity time.Time
    mu           sync.Mutex
}

func (ka *keepAlive) run() {
    for {
        select {
        case <-ka.ticker.C:
            ka.mu.Lock()
            idle := time.Since(ka.lastActivity)
            ka.mu.Unlock()
            
            if idle > ka.interval {
                ka.ping()
            }
        case <-ka.done:
            ka.ticker.Stop()
            return
        }
    }
}

// CRITICAL: Check pool state before pinging to avoid "Busy Trap"
// Don't ping during Opening, Closing, or other transitional states
func (ka *keepAlive) ping() {
    ka.client.mu.RLock()
    pool := ka.client.psrpPool
    if pool == nil {
        ka.client.mu.RUnlock()
        return
    }
    state := pool.State()
    ka.client.mu.RUnlock()
    
    // ONLY ping if pool is in stable Opened state
    if state != runspace.StateOpened {
        return
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Send GET_AVAILABLE_RUNSPACES message (0x00021007)
    // NOTE: Need to add NewGetAvailableRunspaces() to go-psrpcore/messages
    msg := messages.NewGetAvailableRunspaces(pool.ID())
    if err := pool.SendMessage(ctx, msg); err != nil {
        // Ping failed - trigger disconnect detection
        ka.client.handlePingFailure(err)
    }
}
```

**go-psrpcore Addition Required:**

```go
// messages/messages.go - ADD THIS HELPER
// NewGetAvailableRunspaces creates a GET_AVAILABLE_RUNSPACES message.
// Used for keep-alive pings to verify the RunspacePool is still responsive.
// Reference: MS-PSRP 2.2.2.6
func NewGetAvailableRunspaces(runspaceID uuid.UUID) *Message {
    return &Message{
        Destination: DestinationServer,
        Type:        MessageTypeGetAvailableRunspaces,
        RunspaceID:  runspaceID,
        PipelineID:  uuid.Nil,
        Data:        nil, // No payload required
    }
}
```

**Client-Side Concurrency Control (per ChatGPT review):**

> **Why this matters:** If many callers create pipelines at once, the server may queue
> or deny them. A client-side semaphore prevents thundering herd and gives predictable latency.

```go
// client/pool_semaphore.go

type poolSemaphore struct {
    sem       chan struct{}
    maxSize   int
    queueSize int32 // atomic
    maxQueue  int
    timeout   time.Duration
}

func newPoolSemaphore(maxRunspaces, maxQueue int, timeout time.Duration) *poolSemaphore {
    return &poolSemaphore{
        sem:      make(chan struct{}, maxRunspaces),
        maxSize:  maxRunspaces,
        maxQueue: maxQueue,
        timeout:  timeout,
    }
}

// Acquire blocks until a runspace slot is available or timeout/cancel
func (ps *poolSemaphore) Acquire(ctx context.Context) error {
    // Check queue limit
    qLen := atomic.AddInt32(&ps.queueSize, 1)
    defer atomic.AddInt32(&ps.queueSize, -1)
    
    if ps.maxQueue > 0 && int(qLen) > ps.maxQueue {
        return ErrQueueFull
    }
    
    select {
    case ps.sem <- struct{}{}:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    case <-time.After(ps.timeout):
        return ErrAcquireTimeout
    }
}

// Release returns a runspace slot to the pool
func (ps *poolSemaphore) Release() {
    select {
    case <-ps.sem:
    default:
        // Already released or bug - log warning
    }
}

// Stats returns current pool utilization
func (ps *poolSemaphore) Stats() (active, queued, max int) {
    return len(ps.sem), int(atomic.LoadInt32(&ps.queueSize)), ps.maxSize
}

// Integration with Execute:
func (c *Client) Execute(ctx context.Context, script string) (*Result, error) {
    // Acquire semaphore slot before creating pipeline
    if err := c.semaphore.Acquire(ctx); err != nil {
        return nil, fmt.Errorf("pool busy: %w", err)
    }
    defer c.semaphore.Release()
    
    // ... rest of execute logic
}
```

**Pool Health States (per ChatGPT review):**

> **Why this matters:** Servers can silently close shells. The client must detect this
> and either re-create the pool or fail fast with exponential backoff.

```go
// client/health.go

type PoolHealth int

const (
    PoolHealthy    PoolHealth = iota // All good
    PoolDegraded                      // Some failures, still usable
    PoolUnhealthy                     // Ping failed, needs recreation
    PoolClosed                        // Permanently closed
)

type healthManager struct {
    health         PoolHealth
    consecutiveFails int
    lastPingTime   time.Time
    lastPingErr    error
    mu             sync.RWMutex
    
    // Thresholds
    degradedThreshold  int           // Failures before Degraded
    unhealthyThreshold int           // Failures before Unhealthy
    recreateBackoff    time.Duration // Exponential backoff base
}

func (hm *healthManager) recordPingSuccess() {
    hm.mu.Lock()
    defer hm.mu.Unlock()
    hm.consecutiveFails = 0
    hm.lastPingTime = time.Now()
    hm.lastPingErr = nil
    hm.health = PoolHealthy
}

func (hm *healthManager) recordPingFailure(err error) PoolHealth {
    hm.mu.Lock()
    defer hm.mu.Unlock()
    
    hm.consecutiveFails++
    hm.lastPingErr = err
    
    switch {
    case hm.consecutiveFails >= hm.unhealthyThreshold:
        hm.health = PoolUnhealthy
    case hm.consecutiveFails >= hm.degradedThreshold:
        hm.health = PoolDegraded
    }
    
    return hm.health
}

// Auto-recreate logic with exponential backoff
func (c *Client) handleUnhealthyPool(ctx context.Context) error {
    backoff := c.healthMgr.recreateBackoff
    
    for attempt := 1; attempt <= 3; attempt++ {
        // Fail all in-flight pipelines with retriable error
        c.failActivePipelines(ErrPoolRecreating)
        
        // Close old pool
        c.cleanupOldConnection()
        
        // Try to recreate
        if err := c.doConnect(ctx); err != nil {
            select {
            case <-time.After(backoff):
                backoff *= 2
            case <-ctx.Done():
                return ctx.Err()
            }
            continue
        }
        
        c.healthMgr.recordPingSuccess()
        return nil
    }
    
    c.healthMgr.mu.Lock()
    c.healthMgr.health = PoolClosed
    c.healthMgr.mu.Unlock()
    
    return ErrPoolRecreationFailed
}
```

**Atomic CI (Call ID) Management (per ChatGPT review):**

> **Why this matters:** MS-PSRP requires unique integer call IDs. Using atomic counters
> avoids mutex contention on the hot path.

```go
// client/call_id.go

type callIDManager struct {
    counter  uint64
    pending  sync.Map // callID -> chan *messages.Message
}

func (cm *callIDManager) nextID() uint64 {
    return atomic.AddUint64(&cm.counter, 1)
}

// Register a pending request and return completion channel
func (cm *callIDManager) register(id uint64) <-chan *messages.Message {
    ch := make(chan *messages.Message, 1)
    cm.pending.Store(id, ch)
    return ch
}

// Complete a pending request
func (cm *callIDManager) complete(id uint64, msg *messages.Message) {
    if val, ok := cm.pending.LoadAndDelete(id); ok {
        ch := val.(chan *messages.Message)
        select {
        case ch <- msg:
        default:
        }
        close(ch)
    }
}

// Timeout cleanup for abandoned requests
func (cm *callIDManager) expire(id uint64) {
    cm.pending.Delete(id)
}
```

**Deliverable:** Stable connection lifecycle; shell stays alive across multiple Execute() calls.

**Test Criteria:**

- [ ] 1000 sequential commands with single Connect/Close
- [ ] Shell survives 5 minutes idle (keep-alive working)
- [ ] Graceful shutdown waits for active pipelines
- [ ] All tests pass with `-race` flag
- [ ] Semaphore limits concurrent pipelines to MaxRunspaces
- [ ] Queue backpressure: N goroutines > MaxRunspaces handled correctly

**Close Strategies (per ChatGPT review):**

```go
// client/close.go

type CloseStrategy int

const (
    // CloseWait waits for active pipelines to finish (up to timeout)
    CloseWait CloseStrategy = iota
    // CloseCancel cancels all pipelines immediately via context
    CloseCancel
    // CloseForce sends STOP signal and forcibly closes
    CloseForce
)

func (c *Client) Close(ctx context.Context) error {
    return c.CloseWithStrategy(ctx, CloseWait)
}

func (c *Client) CloseWithStrategy(ctx context.Context, strategy CloseStrategy) error {
    c.mu.Lock()
    if c.closed {
        c.mu.Unlock()
        return nil
    }
    c.closed = true
    c.mu.Unlock()
    
    // Stop keep-alive
    if c.keepAlive != nil {
        close(c.keepAlive.done)
    }
    
    switch strategy {
    case CloseWait:
        // Wait for pipelines with timeout
        return c.waitForPipelines(ctx)
    case CloseCancel:
        // Cancel all pipeline contexts
        c.cancelAllPipelines()
        return c.closePool(ctx)
    case CloseForce:
        // Send STOP to all, then close immediately
        c.stopAllPipelines(ctx)
        return c.closePool(ctx)
    }
    
    return c.closePool(ctx)
}

func (c *Client) waitForPipelines(ctx context.Context) error {
    done := make(chan struct{})
    go func() {
        c.activePipelines.Range(func(_, v interface{}) bool {
            ap := v.(*activePipeline)
            <-ap.done
            return true
        })
        close(done)
    }()
    
    select {
    case <-done:
        return c.closePool(ctx)
    case <-ctx.Done():
        // Timeout - force close
        c.stopAllPipelines(ctx)
        return c.closePool(ctx)
    }
}
```

---

#### Phase M2: Multiplexing (Week 3-4)

**Goal:** Shell reuse with concurrent pipeline execution.

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| M2.1 | `ExecuteAsync()` - background execution with Future | 8 | P0 |
| M2.2 | `ExecuteStream()` - expose pipeline channels for streaming | 6 | P0 |
| M2.3 | Pool configuration in Config struct | 4 | P0 |
| M2.4 | Pipeline builder fluent API | 6 | P1 |
| M2.5 | Test: 5 concurrent pipelines | 4 | P0 |
| M2.6 | Test: Large output streaming (no OOM) | 4 | P0 |
| M2.7 | Benchmarks: latency comparison | 4 | P1 |
| M2.8 | **Handle RUNSPACE_AVAILABILITY responses** | 4 | P1 |
| M2.9 | **Transport-agnostic keepalive interface** | 4 | P1 |

**ExecuteAsync API:**

> **Memory Warning (per Gemini review):**
> `ExecuteAsync` collects ALL output into memory slices. Running `Get-ChildItem -Recurse`
> on a large filesystem will OOM your process. Use `ExecuteStream` for large/unknown outputs.
>
> This is by design: `ExecuteAsync` is for "fire and forget" of **bounded** commands.
> Document this clearly and consider adding a `MaxOutputItems` safety limit.

```go
// client/async.go

// Future represents an asynchronous pipeline execution.
// WARNING: All output is collected in memory. For large outputs, use ExecuteStream.
type Future struct {
    pipeline *pipeline.Pipeline
    stream   *StreamResult  // Wraps StreamResult internally
    done     chan struct{}
    result   *Result
    err      error
    mu       sync.Mutex
}

// ExecuteAsync runs a script asynchronously and collects results in memory.
// WARNING: For commands with large/unbounded output, use ExecuteStream instead
// to avoid OOM. This method is intended for bounded commands where you want
// the convenience of getting all results at once.
func (c *Client) ExecuteAsync(ctx context.Context, script string) (*Future, error) {
    // Internally use streaming, but collect to memory
    stream, err := c.ExecuteStream(ctx, script)
    if err != nil {
        return nil, err
    }
    
    f := &Future{
        pipeline: stream.pipeline,
        stream:   stream,
        done:     make(chan struct{}),
    }
    
    go func() {
        defer close(f.done)
        f.result, f.err = f.collectFromStream(ctx)
    }()
    
    // Start the stream after setting up collector
    if err := stream.Start(); err != nil {
        return nil, err
    }
    
    return f, nil
}

// collectFromStream drains stream channels into memory slices
func (f *Future) collectFromStream(ctx context.Context) (*Result, error) {
    var output, errors []interface{}
    deser := serialization.NewDeserializer()
    defer deser.Close()
    
    // Drain all channels concurrently
    var wg sync.WaitGroup
    var mu sync.Mutex
    
    wg.Add(2)
    go func() {
        defer wg.Done()
        for msg := range f.stream.Output {
            objs, _ := deser.Deserialize(msg.Data)
            mu.Lock()
            output = append(output, objs...)
            mu.Unlock()
        }
    }()
    go func() {
        defer wg.Done()
        for msg := range f.stream.Errors {
            objs, _ := deser.Deserialize(msg.Data)
            mu.Lock()
            errors = append(errors, objs...)
            mu.Unlock()
        }
    }()
    
    wg.Wait()
    
    if err := f.stream.Wait(); err != nil {
        return nil, err
    }
    
    return &Result{
        Output:    output,
        Errors:    errors,
        HadErrors: len(errors) > 0,
    }, nil
}

func (f *Future) Wait(ctx context.Context) (*Result, error) {
    select {
    case <-f.done:
        return f.result, f.err
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}

func (f *Future) Ready() bool {
    select {
    case <-f.done:
        return true
    default:
        return false
    }
}

// Stop cancels the async execution
func (f *Future) Stop() error {
    return f.stream.Stop()
}
```

**ExecuteStream API:**

> **Race Condition Note (per Gemini review):**
> If we call `Invoke()` before returning channels to the user, a very fast server could
> fill the buffer before the user starts draining. With 100-item buffers this is low risk,
> but cleaner architecture has user call `Start()` explicitly.

```go
// client/stream.go

type StreamResult struct {
    pipeline *pipeline.Pipeline
    ctx      context.Context
    cancel   context.CancelFunc
    cleanup  func()
    started  bool
    mu       sync.Mutex
    
    // Direct channel access (available after creation, before Start)
    Output      <-chan *messages.Message
    Errors      <-chan *messages.Message
    Warnings    <-chan *messages.Message
    Verbose     <-chan *messages.Message
    Debug       <-chan *messages.Message
    Progress    <-chan *messages.Message
    Information <-chan *messages.Message
}

func (c *Client) ExecuteStream(ctx context.Context, script string) (*StreamResult, error) {
    pl, cleanup, err := c.preparePipeline(ctx, script)
    if err != nil {
        return nil, err
    }
    
    // Return channels BEFORE invoking - user can set up draining first
    return &StreamResult{
        pipeline: pl,
        ctx:      ctx,
        cleanup:  cleanup,
        Output:   pl.Output(),
        Errors:   pl.Error(),
        // ... other streams
    }, nil
}

// Start begins pipeline execution. Call this AFTER setting up channel consumers.
// This prevents race conditions where fast servers fill buffers before user is ready.
func (sr *StreamResult) Start() error {
    sr.mu.Lock()
    defer sr.mu.Unlock()
    
    if sr.started {
        return errors.New("stream already started")
    }
    sr.started = true
    
    return sr.pipeline.Invoke(sr.ctx)
}

// Wait blocks until pipeline completes and performs cleanup.
func (sr *StreamResult) Wait() error {
    defer sr.cleanup()
    return sr.pipeline.Wait()
}

// Stop sends SIGNAL to terminate the pipeline.
func (sr *StreamResult) Stop() error {
    return sr.pipeline.Stop(sr.ctx)
}
```

**Correct Usage Pattern:**

```go
// Get channels first
stream, _ := client.ExecuteStream(ctx, "Get-ChildItem -Recurse C:\\")

// Set up consumer goroutine BEFORE starting
go func() {
    for msg := range stream.Output {
        obj := deserialize(msg)
        fmt.Println(obj)  // Process immediately, no buffering
    }
}()

// NOW start execution - server output goes directly to consumer
stream.Start()
stream.Wait()
```

**Deliverable:** Concurrent execution, streaming API, significant latency improvement.

**Test Criteria:**

- [ ] 5 concurrent pipelines complete successfully
- [ ] ExecuteStream handles 100MB output without OOM
- [ ] Subsequent execution latency <100ms (vs 1-2s baseline)
- [ ] All tests pass with `-race` flag

**RUNSPACE_AVAILABILITY Handling (per ChatGPT review):**

> **Why this matters:** Servers may restrict max runspaces. The client must parse
> RUNSPACE_AVAILABILITY messages and update local available count.

```go
// client/availability.go

type availabilityTracker struct {
    available     int32 // atomic - current available runspaces
    serverMax     int   // what server negotiated
    mu            sync.RWMutex
}

// HandleRunspaceAvailability processes RUNSPACE_AVAILABILITY messages
// and unlocks queued pipeline creators as appropriate
func (at *availabilityTracker) HandleRunspaceAvailability(msg *messages.Message) {
    // Parse availability count from CLIXML payload
    // Update available count
    // Signal waiting goroutines if slots opened up
}

// Called during Connect to record negotiated limits
func (at *availabilityTracker) SetServerLimits(min, max int) {
    at.mu.Lock()
    defer at.mu.Unlock()
    at.serverMax = max
    atomic.StoreInt32(&at.available, int32(max))
}
```

**Transport-Agnostic Keepalive (per ChatGPT review):**

> **Why this matters:** WinRM vs SSH have different lifecycle semantics.
> Abstract keepalive so each transport can implement efficiently.

```go
// transport/transport.go

// Transport is the interface for PSRP transports
type Transport interface {
    // SendMessage sends a PSRP message
    SendMessage(ctx context.Context, msg *messages.Message) error
    // ReceiveMessage receives a PSRP message
    ReceiveMessage(ctx context.Context) (*messages.Message, error)
    // Close closes the transport
    Close(ctx context.Context) error
    
    // KeepAlive sends transport-appropriate keepalive
    // WSMan: GET_AVAILABLE_RUNSPACES
    // SSH: empty Receive or NOP
    KeepAlive(ctx context.Context) error
    
    // Capabilities returns transport capabilities
    Capabilities() TransportCapabilities
}

type TransportCapabilities struct {
    SupportsDisconnect  bool // WSMan: yes, SSH: no
    SupportsReconnect   bool
    MaxFragmentSize     int
    KeepAliveMethod     string // "psrp" or "transport"
}

// WSMan transport keepalive
func (t *WSManTransport) KeepAlive(ctx context.Context) error {
    // Send GET_AVAILABLE_RUNSPACES and wait for response
    msg := messages.NewGetAvailableRunspaces(t.runspaceID)
    return t.SendMessage(ctx, msg)
}

// SSH/OutOfProc transport keepalive  
func (t *SSHTransport) KeepAlive(ctx context.Context) error {
    // SSH has its own keepalive; just verify connection
    return t.conn.SetDeadline(time.Now().Add(10 * time.Second))
}
```

---

#### Phase M3: Basic Resilience (Week 5-6)

**Goal:** Graceful error handling and optional reconnection on network failures.

> **Critical Design Decision (per Gemini review):**
>
> **Do NOT implement transparent auto-reconnect for v1.**
>
> **Reason:** PSRP Runspaces are *stateful*. If the connection dies, PowerShell variables
> (`$myVar = 1`) and session state are **lost**. If we silently reconnect and re-run the
> command, users get confusing errors because their variables are gone.
>
> **Better approach:** Implement `client.Reconnect(ctx)` that users call explicitly
> after detecting an error, so they **know** the state has been reset.
>
> **Auto-retry is ONLY safe for:**
>
> - Stateless commands (no variable dependencies)
> - Commands explicitly marked as idempotent
> - When the user opts in via configuration

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| M3.1 | Connection state tracking (`connState`, `connErr`) | 4 | P0 |
| M3.2 | `ensureConnected()` pre-Execute health check | 4 | P0 |
| M3.3 | Recoverable error detection | 4 | P0 |
| M3.4 | `Reconnect(ctx)` method for explicit reconnection | 6 | P0 |
| M3.5 | Optional auto-retry for stateless commands (opt-in) | 6 | P1 |
| M3.6 | `OnStateChange()` notification channel | 4 | P1 |
| M3.7 | `IsHealthy()` explicit health check method | 2 | P2 |
| M3.8 | Keep-alive triggers disconnect detection | 4 | P0 |
| M3.9 | In-flight pipeline failure handling | 6 | P0 |
| M3.10 | Integration tests with simulated failures | 8 | P0 |

**Configuration:**

```go
type ResilienceMode int

const (
    // ResilienceNone - No automatic recovery (current behavior)
    ResilienceNone ResilienceMode = iota
    
    // ResilienceReconnect - Auto-reconnect on failure, lose in-flight data
    ResilienceReconnect
    
    // ResilienceResume - Reconnect AND resume buffered output (Phase M4)
    ResilienceResume
)

type Config struct {
    // ... existing fields ...
    
    // Resilience settings
    Resilience           ResilienceMode
    MaxReconnectAttempts int           // Default: 3
    ReconnectBackoff     time.Duration // Default: 1s, doubles each attempt
}
```

**Reconnection Implementation:**

```go
// client/resilient.go

// ConnectionError wraps errors with connection state information
type ConnectionError struct {
    Err         error
    Recoverable bool  // True if Reconnect() might fix it
    StateLost   bool  // True if PowerShell variables are gone
}

func (e *ConnectionError) Error() string {
    return e.Err.Error()
}

func (e *ConnectionError) Unwrap() error {
    return e.Err
}

func (c *Client) Execute(ctx context.Context, script string) (*Result, error) {
    // Check connection health first
    if err := c.ensureConnected(ctx); err != nil {
        return nil, &ConnectionError{
            Err:         fmt.Errorf("not connected: %w", err),
            Recoverable: true,
            StateLost:   true,
        }
    }
    
    result, err := c.doExecute(ctx, script)
    if err == nil {
        return result, nil
    }
    
    // Wrap with connection info if it's a transport error
    if c.isTransportError(err) {
        return nil, &ConnectionError{
            Err:         err,
            Recoverable: true,
            StateLost:   true, // Always true - reconnect means new session
        }
    }
    
    return nil, err
}

// Reconnect explicitly reconnects after a connection failure.
// WARNING: This creates a NEW RunspacePool. All PowerShell variables
// and session state from the previous connection are LOST.
// The caller is responsible for re-initializing any required state.
func (c *Client) Reconnect(ctx context.Context) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    // Clean up old connection
    c.cleanupOldConnection()
    
    backoff := c.config.ReconnectBackoff
    if backoff == 0 {
        backoff = time.Second
    }
    
    var lastErr error
    for attempt := 1; attempt <= c.config.MaxReconnectAttempts; attempt++ {
        if err := c.doConnect(ctx); err != nil {
            lastErr = err
            if attempt == c.config.MaxReconnectAttempts {
                break
            }
            select {
            case <-time.After(backoff):
                backoff *= 2
            case <-ctx.Done():
                return ctx.Err()
            }
            continue
        }
        
        // Notify listeners
        c.notifyStateChange(StateConnected, nil)
        return nil
    }
    
    c.connState = StateBroken
    return fmt.Errorf("reconnect failed after %d attempts: %w", 
        c.config.MaxReconnectAttempts, lastErr)
}

// ExecuteStateless executes a command that has no dependencies on session state.
// If the connection fails, it will automatically reconnect and retry.
// Use this for idempotent operations only.
func (c *Client) ExecuteStateless(ctx context.Context, script string) (*Result, error) {
    result, err := c.Execute(ctx, script)
    if err == nil {
        return result, nil
    }
    
    // Check if we should auto-retry
    var connErr *ConnectionError
    if !errors.As(err, &connErr) || !connErr.Recoverable {
        return nil, err
    }
    
    if c.config.Resilience < ResilienceReconnect {
        return nil, err // User hasn't opted into auto-retry
    }
    
    // Reconnect and retry
    if err := c.Reconnect(ctx); err != nil {
        return nil, fmt.Errorf("auto-retry failed: %w", err)
    }
    
    return c.Execute(ctx, script)
}
```

**Usage Pattern:**

```go
// Standard usage - caller handles reconnection
result, err := client.Execute(ctx, "$x = 1; $x + 1")
if err != nil {
    var connErr *client.ConnectionError
    if errors.As(err, &connErr) && connErr.Recoverable {
        // Connection died - we need to reconnect
        // WARNING: $x is now gone!
        if err := client.Reconnect(ctx); err != nil {
            log.Fatal("Cannot reconnect:", err)
        }
        // Re-initialize state and retry
        result, err = client.Execute(ctx, "$x = 1; $x + 1")
    }
}

// For stateless/idempotent commands - auto-retry is safe
cfg.Resilience = client.ResilienceReconnect
result, err := client.ExecuteStateless(ctx, "Get-Date") // No state dependencies
```

**Deliverable:** Auto-recovery from network failures; production-ready stability.

**Test Criteria:**

- [ ] Recovers from simulated network failure
- [ ] Exponential backoff works correctly
- [ ] OnStateChange notifies on disconnect/reconnect
- [ ] In-flight pipelines fail gracefully with clear error

---

#### Phase M4: Full Resilience (Week 7-8) - Optional/Enterprise

**Goal:** Session persistence and resumable execution.

| # | Task | Est. Hours | Priority |
|---|------|------------|----------|
| M4.1 | WSMan Disconnect message implementation | 6 | P1 |
| M4.2 | WSMan Reconnect message implementation | 6 | P1 |
| M4.3 | `OutputBufferingMode` configuration (Drop/Block) | 4 | P1 |
| M4.4 | `SessionStore` interface | 4 | P1 |
| M4.5 | `FileSessionStore` implementation | 6 | P1 |
| M4.6 | `ResilientResult` with resume capability | 8 | P1 |
| M4.7 | `Disconnect()` graceful disconnect method | 4 | P1 |
| M4.8 | Reconnect to existing session logic | 8 | P1 |
| M4.9 | Pipeline state restoration | 6 | P2 |
| M4.10 | Integration tests with process restart | 8 | P1 |

**Session Store Interface:**

```go
// client/session_store.go

// SessionStore persists session state for recovery across process restarts
type SessionStore interface {
    Save(ctx context.Context, session *SessionState) error
    Load(ctx context.Context, hostname string) (*SessionState, error)
    Delete(ctx context.Context, hostname string) error
    List(ctx context.Context) ([]*SessionState, error)
}

// SessionState contains everything needed to reconnect
type SessionState struct {
    Hostname       string
    ShellID        string        // WSMan Shell ID
    RunspaceID     uuid.UUID     // PSRP RunspacePool ID
    SessionID      string        // WSMan Session ID
    Pipelines      []PipelineState
    CreatedAt      time.Time
    DisconnectedAt time.Time
    ExpiresAt      time.Time     // Based on DisconnectTimeout
}
```

**WSMan Disconnect/Reconnect:**

```go
// wsman/client.go additions

const (
    ActionDisconnect = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect"
    ActionReconnect  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect"
)

func (c *Client) Disconnect(ctx context.Context, shellID string, bufferMode string) error {
    body := fmt.Sprintf(`
        <rsp:Disconnect xmlns:rsp="%s">
            <rsp:BufferMode>%s</rsp:BufferMode>
        </rsp:Disconnect>
    `, ResourceURIPowerShell, bufferMode)
    
    req := c.newRequest(ActionDisconnect, shellID, "", body)
    _, err := c.send(ctx, req)
    return err
}

func (c *Client) Reconnect(ctx context.Context, shellID string) error {
    body := fmt.Sprintf(`<rsp:Reconnect xmlns:rsp="%s"/>`, ResourceURIPowerShell)
    req := c.newRequest(ActionReconnect, shellID, "", body)
    _, err := c.send(ctx, req)
    return err
}
```

**Resilient Execution:**

```go
// client/resilient_result.go

type ResilientResult struct {
    client   *Client
    pipeline *pipeline.Pipeline
    script   string
    output   []interface{}
    errors   []interface{}
    resumed  bool
    mu       sync.RWMutex
}

// Wait blocks until completion, automatically handling disconnects
func (rr *ResilientResult) Wait(ctx context.Context) (*Result, error) {
    for {
        result, err := rr.waitOnce(ctx)
        if err == nil {
            return result, nil
        }
        
        if !rr.client.isRecoverableError(err) {
            return nil, err
        }
        
        // Attempt to resume
        if err := rr.resume(ctx); err != nil {
            return nil, fmt.Errorf("failed to resume: %w", err)
        }
        
        rr.mu.Lock()
        rr.resumed = true
        rr.mu.Unlock()
    }
}

func (rr *ResilientResult) WasResumed() bool {
    rr.mu.RLock()
    defer rr.mu.RUnlock()
    return rr.resumed
}
```

**Deliverable:** Crash-recovery capable client; enterprise-grade resilience.

**Test Criteria:**

- [ ] Graceful disconnect keeps session alive on server
- [ ] Can reconnect after client restart
- [ ] Buffered output received after reconnect
- [ ] Session expires after configured timeout

---

### Configuration Reference

```go
// Default: Fast but simple
func DefaultConfig() Config {
    return Config{
        Timeout:      60 * time.Second,
        MinRunspaces: 1,
        MaxRunspaces: 5,
        Resilience:   ResilienceNone,
    }
}

// Production: Auto-recovery from failures
func ProductionConfig() Config {
    return Config{
        Timeout:              60 * time.Second,
        MinRunspaces:         1,
        MaxRunspaces:         10,
        Resilience:           ResilienceReconnect,
        MaxReconnectAttempts: 3,
        ReconnectBackoff:     time.Second,
        KeepAliveInterval:    30 * time.Second,
    }
}

// Enterprise: Full resilience with session persistence
func EnterpriseConfig(sessionDir string) Config {
    store, _ := NewFileSessionStore(sessionDir)
    return Config{
        Timeout:              60 * time.Second,
        MinRunspaces:         1,
        MaxRunspaces:         10,
        Resilience:           ResilienceResume,
        MaxReconnectAttempts: 5,
        ReconnectBackoff:     time.Second,
        KeepAliveInterval:    30 * time.Second,
        OutputBufferingMode:  OutputBufferingBlock,
        DisconnectTimeout:    4 * time.Hour,
        SessionStore:         store,
    }
}
```

### Success Metrics

**Functional:**

- [ ] Execute 1000 commands with single Connect/Close
- [ ] Run 5 concurrent pipelines successfully
- [ ] Graceful shutdown with active pipelines
- [ ] Auto-recover from network failure
- [ ] Resume long-running task after disconnect (Phase M4)
- [ ] All tests pass with `-race` flag

**Performance:**

| Metric | Baseline | Target |
|--------|----------|--------|
| First execution | 1-2s | 1-2s (unchanged) |
| Subsequent execution | 1-2s | <100ms |
| 5 concurrent pipelines | 10s (serial) | ~2s (parallel) |
| Memory under load | OOM risk | Stable (streaming) |

### Usage Examples

```go
// Example 1: Basic multiplexing (fast repeated commands)
cfg := client.DefaultConfig()
c, _ := client.New("server.example.com", cfg)
c.Connect(ctx)
defer c.Close(ctx)

for i := 0; i < 100; i++ {
    result, _ := c.Execute(ctx, "Get-Date")  // <100ms after first
    fmt.Println(result.Output[0])
}

// Example 2: Concurrent execution
var futures []*client.Future
for _, server := range servers {
    f, _ := c.ExecuteAsync(ctx, fmt.Sprintf("Test-Connection %s", server))
    futures = append(futures, f)
}
for _, f := range futures {
    result, _ := f.Wait(ctx)
    // Process results...
}

// Example 3: Streaming large output
stream, _ := c.ExecuteStream(ctx, "Get-ChildItem -Recurse C:\\Windows")
for msg := range stream.Output {
    obj := deserialize(msg)
    fmt.Println(obj.Name)  // Process one at a time, no buffering
}

// Example 4: Auto-reconnect on failure
cfg := client.ProductionConfig()
c, _ := client.New("server.example.com", cfg)
c.Connect(ctx)

// If network blips, automatically retries
result, err := c.Execute(ctx, "Get-Process")

// Example 5: Full resilience with session persistence
cfg := client.EnterpriseConfig("/var/lib/myapp/sessions")
c, _ := client.New("server.example.com", cfg)

// May reconnect to session from previous run!
c.Connect(ctx)

rr, _ := c.ExecuteResilient(ctx, longRunningScript)
result, _ := rr.Wait(ctx)  // Survives disconnects
if rr.WasResumed() {
    log.Println("Recovered from disconnect!")
}

// Example 6: Graceful disconnect for maintenance
c.Connect(ctx)
rr, _ := c.ExecuteResilient(ctx, longScript)

c.Disconnect(ctx)  // Server keeps running
// ... later, maybe different process ...
c.Connect(ctx)     // Reconnects to same session
result, _ := rr.Wait(ctx)
```

### Timeline Summary

| Week | Phase | Focus | Deliverables |
|------|-------|-------|-------------|
| 1-2 | M1 | Foundation | Dispatch fix, state tracking, keep-alive, **semaphore**, **health states**, **CI table** |
| 3-4 | M2 | Multiplexing | ExecuteAsync, ExecuteStream, pool config, **RUNSPACE_AVAILABILITY**, **transport interface** |
| 5-6 | M3 | Basic Resilience | Explicit reconnect, health checks, notifications, **close strategies** |
| 7-8 | M4 | Full Resilience | WSMan Disconnect/Reconnect, session persistence, **metrics/observability** |

### Prioritized Implementation Checklist

(Consolidated from Gemini + ChatGPT reviews)

| # | Task | Phase | Priority |
|---|------|-------|----------|
| 1 | Fix dispatch loop (move `StartDispatchLoop` to `Connect`) | M1 | P0 |
| 2 | Add atomic CI counter + pending request table | M1 | P0 |
| 3 | Implement client-side semaphore tied to MaxRunspaces | M1 | P0 |
| 4 | Implement keep-alive + pool health states + auto-recreate | M1 | P0 |
| 5 | Add state check in `ping()` (avoid "Busy Trap") | M1 | P0 |
| 6 | Implement `ExecuteStream` with `Start()` pattern | M2 | P0 |
| 7 | Implement `ExecuteAsync` wrapping `ExecuteStream` | M2 | P0 |
| 8 | Handle RUNSPACE_AVAILABILITY messages | M2 | P1 |
| 9 | Add transport-agnostic keepalive interface | M2 | P1 |
| 10 | Implement explicit `Reconnect()` method | M3 | P0 |
| 11 | Add `ConnectionError` with `Recoverable`/`StateLost` flags | M3 | P0 |
| 12 | Implement `CloseWithStrategy(Wait/Cancel/Force)` | M3 | P1 |
| 13 | Add metrics (`Metrics()`, `PrometheusMetrics()`) | M3 | P2 |
| 14 | Implement benchmark harness | M3 | P2 |
| 15 | WSMan Disconnect/Reconnect messages | M4 | P1 |
| 16 | Session persistence (`SessionStore`) | M4 | P1 |

### Gemini Review Notes

The following feedback was incorporated from expert review:

| Issue | Resolution |
|-------|------------|
| **Keep-Alive ≠ Auto-Reconnect** | Clarified in docs. Keep-alive prevents timeout; it doesn't recover from network failures. |
| **"Busy Trap"** | Added state check in `ping()` - only ping when `pool.State() == StateOpened` |
| **Streaming Race Condition** | Changed `ExecuteStream` to return channels first, user calls `Start()` explicitly |
| **GetAvailableRunspaces missing** | Need to add `NewGetAvailableRunspaces()` helper to go-psrpcore |
| **ExecuteAsync OOM risk** | Documented warning; ExecuteAsync wraps StreamResult but collects to memory |
| **Transparent reconnect danger** | Changed to explicit `Reconnect()` method. Added `ExecuteStateless()` for opt-in auto-retry. |
| **Variable state loss** | `ConnectionError.StateLost` flag tells caller their `$variables` are gone |

### ChatGPT Review Notes

Additional feedback incorporated from ChatGPT expert review:

| Issue | Resolution |
|-------|------------|
| **Client-side concurrency control** | Added `poolSemaphore` tied to MaxRunspaces to prevent thundering herd |
| **Pool health states** | Added `PoolHealthy/Degraded/Unhealthy` states with auto-recreate logic |
| **CI table / atomic message IDs** | Added `callIDManager` with atomic counter and pending request tracking |
| **RUNSPACE_AVAILABILITY handling** | Added `availabilityTracker` to parse responses and update available count |
| **Close strategies** | Added `CloseWithStrategy(Wait/Cancel/Force)` for deterministic shutdown |
| **Transport-agnostic keepalive** | Added `Transport.KeepAlive()` interface for WSMan vs SSH differences |
| **Metrics/observability** | Added `Metrics()` and `PrometheusMetrics()` for latency tracking |
| **Concrete test list** | Added 10 specific test cases with assertions |
| **Retriable error flags** | `ConnectionError` includes `Retriable` flag for caller retry logic |

**Key Architectural Decisions:**

1. **No transparent auto-reconnect by default** - PSRP runspaces are stateful. Silent reconnection would cause confusing errors when `$myVar` suddenly doesn't exist.

2. **Explicit > Implicit** - Users call `Reconnect()` when they're ready to lose state. `ExecuteStateless()` is opt-in for idempotent commands.

3. **Stream-first architecture** - `ExecuteAsync` wraps `ExecuteStream` internally, ensuring consistent back-pressure handling.

4. **Channels before execution** - `ExecuteStream` returns channels before `Start()` to prevent buffer overflow on fast servers.

5. **Semaphore before server** - Client-side rate limiting prevents overwhelming the server with pipeline requests.

6. **Health-aware recreation** - Pool automatically recreates on consecutive failures with exponential backoff.

### Metrics & Observability (per ChatGPT review)

> **Why this matters:** To validate performance claims ("sub-100ms warm path") you need
> reproducible benchmarks and telemetry.

```go
// client/metrics.go

type Metrics struct {
    // Pool metrics
    PoolReuseCount     uint64 // Times pool was reused vs recreated
    PoolRecreateCount  uint64 // Pool recreation events
    PoolHealth         PoolHealth
    
    // Pipeline metrics
    ActivePipelines    int32
    QueuedPipelines    int32
    CompletedPipelines uint64
    FailedPipelines    uint64
    
    // Latency (nanoseconds)
    LastLatency        int64
    LatencyP50         int64
    LatencyP95         int64
    LatencyP99         int64
    
    // Keep-alive
    LastPingTime       time.Time
    PingFailures       uint64
    
    // Memory
    BytesInFlight      int64
}

func (c *Client) Metrics() *Metrics {
    return &Metrics{
        PoolReuseCount:     atomic.LoadUint64(&c.metrics.poolReuse),
        PoolRecreateCount:  atomic.LoadUint64(&c.metrics.poolRecreate),
        ActivePipelines:    atomic.LoadInt32(&c.metrics.activePipelines),
        QueuedPipelines:    int32(c.semaphore.QueueLength()),
        // ... populate from atomic counters
    }
}

// Prometheus-style export (optional)
func (c *Client) PrometheusMetrics() string {
    m := c.Metrics()
    return fmt.Sprintf(`
# HELP psrp_pool_reuse_total Times the pool was reused
# TYPE psrp_pool_reuse_total counter
psrp_pool_reuse_total %d

# HELP psrp_active_pipelines Current active pipelines
# TYPE psrp_active_pipelines gauge
psrp_active_pipelines %d

# HELP psrp_latency_seconds Pipeline execution latency
# TYPE psrp_latency_seconds histogram
psrp_latency_seconds{quantile="0.5"} %f
psrp_latency_seconds{quantile="0.95"} %f
psrp_latency_seconds{quantile="0.99"} %f
`,
        m.PoolReuseCount,
        m.ActivePipelines,
        float64(m.LatencyP50)/1e9,
        float64(m.LatencyP95)/1e9,
        float64(m.LatencyP99)/1e9,
    )
}
```

**SLO Targets:**

- 95% subsequent commands < 100ms
- First command < 2s
- Pool reuse rate > 99% (minimal recreations)

### Concrete Test Cases (per ChatGPT review)

| Test | Purpose | Assertions |
|------|---------|------------|
| **Pool recreate** | Simulate server closing shell mid-run | Client re-creates pool; in-flight pipelines get retriable errors |
| **Queue backpressure** | N goroutines > MaxRunspaces | No more than MaxRunspaces run concurrently; queued ones wait or timeout |
| **Stream memory** | `Get-ChildItem -Recurse` on deep tree | Memory stays bounded; no OOM |
| **Keepalive** | Set low idle timeout on server | Ping maintains pool; correct behavior if ping fails |
| **Race detector** | All concurrency code | `go test -race` passes |
| **Latency benchmark** | 1000 sequential commands | P50 < 100ms for commands 2-1000 |
| **Concurrent benchmark** | 100 concurrent pipelines | Total time < 10x single execution |
| **CI table cleanup** | Pending requests with timeout | Abandoned CIs cleaned up; no memory leak |
| **Semaphore fairness** | FIFO ordering | Earlier requests complete before later ones |
| **Health state transitions** | Healthy → Degraded → Unhealthy → Recreate | State machine works correctly |

**Benchmark Harness:**

```go
// client/benchmark_test.go

func BenchmarkSequentialExecute(b *testing.B) {
    client := setupTestClient(b)
    defer client.Close(context.Background())
    
    // Warm up
    client.Execute(context.Background(), "$null")
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := client.Execute(context.Background(), "$null")
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkConcurrentExecute(b *testing.B) {
    client := setupTestClient(b)
    defer client.Close(context.Background())
    
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, err := client.Execute(context.Background(), "$null")
            if err != nil {
                b.Fatal(err)
            }
        }
    })
}
```

### References

- [MS-PSRP Disconnected Sessions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d2512af0-338a-4243-abe4-dd250ba7f975)
- [PowerShell about_Remote_Disconnected_Sessions](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_disconnected_sessions)
- [pypsrp disconnect/reconnect implementation](https://github.com/jborean93/pypsrp/blob/master/src/psrp/_connection/wsman.py)

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

---

### Phase 4.5: Security & Optimization (Completed)

**Goal:** Ensure compliance and optimize file transfer performance.

**Tasks:**

| # | Task | Status |
|---|------|--------|
| 4.5.1 | Optimization: Transport-aware chunk sizes (256KB/1MB) | ✅ Complete |
| 4.5.2 | Optimization: Streaming file transfer (single pipeline) | ✅ Complete |
| 4.5.3 | Optimization: Zero-copy `[]byte` transfer | ✅ Complete |
| 4.5.4 | Safety: `-no-overwrite` flag with atomic check | ✅ Complete |
| 4.5.5 | Usability: Improved error message reporting | ✅ Complete |
| 4.5.6 | Security: NIST 800-92 Logging Audit | ✅ Complete |
| 4.5.7 | Security: Compliance Remediation (Timestamp Restoration) | ✅ Complete |

**Results:**

- Throughput: ~1.12 MB/s (WinRM), ~5 MB/s (HvSocket)
- Compliance: Full NIST 800-92 adherence for audit logs

---
