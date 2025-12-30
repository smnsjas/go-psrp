// Package client provides a high-level API for PowerShell Remoting over WSMan.
package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrp/powershell"
	"github.com/smnsjas/go-psrp/wsman"
	"github.com/smnsjas/go-psrp/wsman/auth"
	"github.com/smnsjas/go-psrp/wsman/transport"
	"github.com/smnsjas/go-psrpcore/messages"
	"github.com/smnsjas/go-psrpcore/runspace"
	"github.com/smnsjas/go-psrpcore/serialization"
)

// AuthType specifies the authentication mechanism.
type AuthType int

const (
	// AuthNegotiate uses SPNEGO - tries Kerberos first, falls back to NTLM.
	// This is the recommended default for most Windows environments.
	AuthNegotiate AuthType = iota
	// AuthBasic uses HTTP Basic authentication.
	AuthBasic
	// AuthNTLM uses NTLM authentication (direct, not via SPNEGO).
	AuthNTLM
	// AuthKerberos uses Kerberos authentication only (no NTLM fallback).
	AuthKerberos
)

// TransportType specifies the transport mechanism.
type TransportType int

const (
	// TransportWSMan uses WSMan (HTTP/HTTPS) transport.
	TransportWSMan TransportType = iota
	// TransportHvSocket uses Hyper-V Socket (PowerShell Direct) transport.
	TransportHvSocket
)

// Config holds configuration for a PSRP client.
type Config struct {
	// Port is the WinRM port (default: 5985 for HTTP, 5986 for HTTPS).
	Port int

	// UseTLS enables HTTPS transport.
	UseTLS bool

	// InsecureSkipVerify skips TLS certificate verification.
	// WARNING: Only use for testing.
	InsecureSkipVerify bool

	// Timeout is the operation timeout.
	Timeout time.Duration

	// AuthType specifies the authentication type (Basic, NTLM, or Kerberos).
	AuthType AuthType

	// Username for authentication.
	Username string

	// Password for authentication.
	Password string

	// Domain for NTLM authentication.
	Domain string

	// Kerberos specific settings
	// Realm is the Kerberos realm (optional, auto-detected from config if empty).
	Realm string
	// Krb5ConfPath is the path to krb5.conf (optional, defaults to /etc/krb5.conf).
	Krb5ConfPath string
	// KeytabPath is the path to the keytab file (optional).
	KeytabPath string
	// CCachePath is the path to the credential cache (optional).
	CCachePath string

	// Transport specifies the transport mechanism (WSMan or HvSocket).
	Transport TransportType

	// VMID is the Hyper-V VM GUID (Required for TransportHvSocket).
	VMID string

	// ConfigurationName is the PowerShell configuration name (Optional, for HvSocket).
	ConfigurationName string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:     5985,
		UseTLS:   false,
		Timeout:  60 * time.Second,
		AuthType: AuthNegotiate, // Kerberos preferred, NTLM fallback
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Username == "" && !auth.SupportsSSO() {
		return errors.New("username is required")
	}

	// For Kerberos and Negotiate auth, password is optional if ccache or keytab is provided
	if c.AuthType == AuthKerberos || c.AuthType == AuthNegotiate {
		// Password not required if ccache or keytab is available
		if c.CCachePath != "" || c.KeytabPath != "" {
			return nil
		}
	}

	// Password required for Basic, NTLM, and Kerberos/Negotiate without ccache
	// Exception: SSO mode (empty username on Windows) doesn't need password
	if c.Password == "" && c.Username != "" {
		return errors.New("password is required")
	}
	return nil
}

// Client is a high-level PSRP client for executing PowerShell commands.
type Client struct {
	mu sync.Mutex

	hostname string
	config   Config
	endpoint string

	transport *transport.HTTPTransport
	wsman     *wsman.Client
	backend   powershell.RunspaceBackend
	psrpPool  *runspace.Pool
	poolID    uuid.UUID
	connected bool
	closed    bool
	messageID uint64 // Tracks PSRP message ObjectID sequence
}

// New creates a new PSRP client.
func New(hostname string, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Build endpoint URL
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	endpoint := fmt.Sprintf("%s://%s:%d/wsman", scheme, hostname, cfg.Port)

	// Create transport with auth
	tr := transport.NewHTTPTransport(
		transport.WithTimeout(cfg.Timeout),
		transport.WithInsecureSkipVerify(cfg.InsecureSkipVerify),
	)

	// Apply authentication
	creds := auth.Credentials{
		Username: cfg.Username,
		Password: cfg.Password,
		Domain:   cfg.Domain,
	}

	var authenticator auth.Authenticator
	switch cfg.AuthType {
	case AuthNegotiate:
		// Try Kerberos first, fall back to NTLM if Kerberos unavailable
		targetSPN := fmt.Sprintf("HTTP/%s", hostname)
		krbCfg := auth.KerberosProviderConfig{
			TargetSPN:    targetSPN,
			Realm:        cfg.Realm,
			Krb5ConfPath: cfg.Krb5ConfPath,
			KeytabPath:   cfg.KeytabPath,
			CCachePath:   cfg.CCachePath,
			Credentials:  &creds,
			UseSSO:       auth.SupportsSSO() && cfg.Username == "",
		}

		provider, err := auth.NewKerberosProvider(krbCfg)
		if err != nil {
			// Kerberos unavailable, fall back to NTLM via Negotiate header
			// go-ntlmssp Negotiator handles Negotiate header with NTLM
			authenticator = auth.NewNTLMAuth(creds)
		} else {
			authenticator = auth.NewNegotiateAuth(provider)
		}
	case AuthNTLM:
		authenticator = auth.NewNTLMAuth(creds)
	case AuthKerberos:
		// Kerberos only - no fallback
		targetSPN := fmt.Sprintf("HTTP/%s", hostname)
		krbCfg := auth.KerberosProviderConfig{
			TargetSPN:    targetSPN,
			Realm:        cfg.Realm,
			Krb5ConfPath: cfg.Krb5ConfPath,
			KeytabPath:   cfg.KeytabPath,
			CCachePath:   cfg.CCachePath,
			Credentials:  &creds,
			UseSSO:       auth.SupportsSSO() && cfg.Username == "",
		}

		provider, err := auth.NewKerberosProvider(krbCfg)
		if err != nil {
			return nil, fmt.Errorf("create kerberos provider: %w", err)
		}
		authenticator = auth.NewNegotiateAuth(provider)
	case AuthBasic:
		authenticator = auth.NewBasicAuth(creds)
	default:
		// Fallback to Negotiate (shouldn't reach here)
		authenticator = auth.NewNTLMAuth(creds)
	}

	// Wrap transport with auth
	tr.Client().Transport = authenticator.Transport(tr.Client().Transport)

	switch cfg.Transport {
	case TransportHvSocket:
		// Convert String VMID to UUID
		if _, err := uuid.Parse(cfg.VMID); err != nil {
			return nil, fmt.Errorf("invalid vmid: %w", err)
		}
		// Create HvSocketBackend
		// We reuse the pool ID logic inside Connect()? No, pool ID is created in Connect().
		// But NewHvSocketBackend takes poolID?
		// Wait, NewHvSocketBackend signature takes poolID.
		// But in Connect(), we generate poolID for the runspace.New call!
		// If HvSocketBackend owns the Adapter (which needs pool ID), we should pass it AFTER creation?
		// Or creating it in Connect()?
		// NewHvSocketBackend currently takes poolID.
		// Problem: RunspaceBackend.Init takes `*runspace.Pool`.
		// `runspace.New` takes `transport`.
		// `HvSocketBackend` Creates the transport (adapter).
		// So `HvSocketBackend` creates `Adapter`. Adapter needs `runspaceGUID`.
		// So `HvSocketBackend` needs `runspaceGUID` (PoolID).

		// This means we must decide PoolID BEFORE creating Backend?
		// But `Client.Connect` logic:
		// 1. Create Backend
		// 2. Connect
		// 3. Get Transport
		// 4. Create Pool (generates ID?) -> wait, runspace.New TAKES id.
		// So we generate ID in Client.Connect before or during.

		// In previous logic (WSMan), Client generates poolID.
		// So Client should generate PoolID in Connect() and pass it?
		// But `c.backend` is created in `New` or `Connect`?
		// In my recent refactor of `Connect`, `c.backend` is created IN `Connect`.
		// YES.

		// So `New` function in `client.go` should NOT create backend?
		// Wait, `New` returns `*Client`. `Client` struct has `backend` field.
		// Currently `New` does NOT create backend. `Connect` does.
		// But `New` sets `wsman` client.

		// So in `New`, we setup `transport` variable.
		// But for HvSocket, we don't need `transport` or `wsman` client.

		// So `New` should be lighter?
		// Existing `New` logic creates `transport.HTTPTransport` and `wsman.NewClient`.
		// This is WSMan specific.

		// If TransportHvSocket, we don't need HTTP transport.
		// Refactor `New` to branch.

		return &Client{
			hostname: hostname,
			config:   cfg,
			endpoint: "", // Not relevant for HvSocket? Or VmId?
			// wsman: nil, // Will be nil for HvSocket
		}, nil

	default: // WSMan
		// ... existing WSMan setup ...
		return &Client{
			hostname:  hostname,
			config:    cfg,
			endpoint:  endpoint,
			transport: tr,
			wsman:     wsman.NewClient(endpoint, tr),
		}, nil
	}
}

// Endpoint returns the WinRM endpoint URL.
func (c *Client) Endpoint() string {
	return c.endpoint
}

// Connect establishes a connection to the remote server.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errors.New("client is closed")
	}
	if c.connected {
		return nil
	}

	// 1. Create Backend
	// Note: We generate poolID here to pass to backend if needed (HvSocket needs it for Adapter)
	c.poolID = uuid.New()

	switch c.config.Transport {
	case TransportHvSocket:
		// Convert VMID
		vmID, _ := uuid.Parse(c.config.VMID) // Validated in New/Validate but parse again or store in Client?
		// New was creating Client. Config has string.
		// We'll parse again.

		c.backend = powershell.NewHvSocketBackend(
			vmID,
			c.config.Domain,
			c.config.Username,
			c.config.Password,
			c.config.ConfigurationName,
			c.poolID,
		)
	default: // WSMan
		// Ensure wsman client is set (it should be from New)
		if c.wsman == nil {
			return fmt.Errorf("wsman client not initialized")
		}
		c.backend = powershell.NewWSManBackend(c.wsman, powershell.NewWSManTransport(nil, "", ""))
	}

	// 2. Connect Backend (Prepare Transport)
	if err := c.backend.Connect(ctx); err != nil {
		return fmt.Errorf("connect backend: %w", err)
	}

	// 3. Get Transport
	transport, ok := c.backend.Transport().(io.ReadWriter)
	if !ok {
		return fmt.Errorf("backend transport does not implement io.ReadWriter")
	}

	// Set Context on transport if it supports it (WSManTransport does)
	// We need type assertion
	if t, ok := transport.(*powershell.WSManTransport); ok {
		t.SetContext(ctx)
	}

	// 4. Create PSRP Pool
	// We use the ID we generated earlier
	c.psrpPool = runspace.New(transport, c.poolID)

	// 5. Init Backend
	if err := c.backend.Init(ctx, c.psrpPool); err != nil {
		return fmt.Errorf("init backend: %w", err)
	}

	// 4. Drain Shell Output (RunspacePoolState) to ensure pool is ready
	// This is critical: if we don't consume the initial Opened state,
	// subsequent pipeline execution might stall or timeout.
	// We use a short timeout for this initial drain
	drainCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Perform one Receive on the Shell (empty command ID)
	// Drain result is discarded - we just need to consume the state message
	// Note: We need the ShellID from the backend
	// TODO: Add ShellID() to RunspaceBackend interface? Yes, we did.
	if c.backend.ShellID() != "" {
		_, _ = c.wsman.Receive(drainCtx, c.backend.ShellID(), "")
	}

	c.connected = true

	// Initialize messageID counter.
	c.messageID = 2

	return nil
}

// Close closes the connection to the remote server.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	// First close the runspace pool (sends RUNSPACEPOOL_STATE=Closed message)
	if c.psrpPool != nil {
		_ = c.psrpPool.Close(ctx)
	}

	// Then close the backend (sends transport-level Close and closes connection)
	if c.backend != nil && c.connected {
		if err := c.backend.Close(ctx); err != nil {
			return fmt.Errorf("close backend: %w", err)
		}
	}

	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected && !c.closed
}

// Result represents the result of a PowerShell command execution.
// All PowerShell output streams are supported.
type Result struct {
	// Output contains deserialized objects from the pipeline output stream.
	// Each element is a Go type: string, int32, int64, bool, float64,
	// *serialization.PSObject, []interface{}, map[string]interface{}, etc.
	Output []interface{}

	// Errors contains deserialized ErrorRecord objects from the error stream.
	// Populated when PowerShell writes to the error stream (non-terminating errors).
	Errors []interface{}

	// Warnings contains deserialized warning messages from Write-Warning.
	Warnings []interface{}

	// Verbose contains deserialized verbose messages from Write-Verbose.
	Verbose []interface{}

	// Debug contains deserialized debug messages from Write-Debug.
	Debug []interface{}

	// Progress contains deserialized progress records from Write-Progress.
	Progress []interface{}

	// Information contains deserialized information records from Write-Information.
	Information []interface{}

	// HadErrors is true if any error records were received or the pipeline failed.
	HadErrors bool
}

// Execute runs a PowerShell script on the remote server.
// The script can be any valid PowerShell code.
// Returns the output and any errors from execution.
func (c *Client) Execute(ctx context.Context, script string) (*Result, error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, errors.New("client not connected")
	}
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client is closed")
	}
	psrpPool := c.psrpPool
	backend := c.backend
	c.mu.Unlock()

	// Create a go-psrpcore pipeline for this execution
	// We use the simple CreatePipeline which defaults to IsScript=true
	// This generates <Cmd>script</Cmd><IsScript>true</IsScript>
	psrpPipeline, err := psrpPool.CreatePipeline(script)
	if err != nil {
		return nil, fmt.Errorf("create pipeline: %w", err)
	}

	// Get the CreatePipeline fragment data (base64) for WSMan encapsulation
	// Note: client maintains c.messageID sequence
	c.mu.Lock()
	c.messageID++
	msgID := c.messageID
	c.mu.Unlock()

	createPipelineData, err := psrpPipeline.GetCreatePipelineDataWithID(msgID)
	if err != nil {
		return nil, fmt.Errorf("get create pipeline data: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(createPipelineData)

	// Prepare the pipeline via the backend
	// This handles WSMan command creation + transport config
	// Or just returns for HvSocket
	cleanup, err := backend.PreparePipeline(ctx, psrpPipeline, payload)
	if err != nil {
		return nil, fmt.Errorf("prepare pipeline: %w", err)
	}
	defer cleanup()

	// Invoke the pipeline (transitions PSRP state)
	// For WSMan, skip logic was handled in PreparePipeline
	if err := psrpPipeline.Invoke(ctx); err != nil {
		return nil, fmt.Errorf("invoke pipeline: %w", err)
	}

	// Start the dispatch loop FIRST - WinRM Receive is a long-poll that must be
	// waiting on the server when we send EOF. The server will respond to the
	// waiting Receive request with the pipeline output after processing EOF.
	psrpPool.StartDispatchLoop()

	// Note: We do NOT call CloseInput() here because go-psrpcore sets
	// <Obj N="NoInput">true</Obj> in the CreatePipeline message.
	// This tells the server to close the input stream immediately after creation.
	// Sending an extra EOF message would be redundant and might confuse the server
	// or cause race conditions. This matches pypsrp behavior.

	// Collect output from all streams concurrently
	var (
		output      []interface{}
		errOutput   []interface{}
		warnings    []interface{}
		verbose     []interface{}
		debug       []interface{}
		progress    []interface{}
		information []interface{}
		hadErrors   bool
		wg          sync.WaitGroup
		mu          sync.Mutex // Protects hadErrors
	)

	// Helper to deserialize messages from a channel
	drainChannel := func(ch <-chan *messages.Message, dest *[]interface{}, markError bool) {
		defer wg.Done()
		for msg := range ch {
			if markError {
				mu.Lock()
				hadErrors = true
				mu.Unlock()
			}
			deser := serialization.NewDeserializer()
			results, err := deser.Deserialize(msg.Data)
			deser.Close()
			if err != nil {
				*dest = append(*dest, string(msg.Data))
				continue
			}
			*dest = append(*dest, results...)
		}
	}

	wg.Add(7)
	go drainChannel(psrpPipeline.Output(), &output, false)
	go drainChannel(psrpPipeline.Error(), &errOutput, true)
	go drainChannel(psrpPipeline.Warning(), &warnings, false)
	go drainChannel(psrpPipeline.Verbose(), &verbose, false)
	go drainChannel(psrpPipeline.Debug(), &debug, false)
	go drainChannel(psrpPipeline.Progress(), &progress, false)
	go drainChannel(psrpPipeline.Information(), &information, false)

	// Wait for all channels to be drained
	wg.Wait()

	// Wait for pipeline completion
	if err := psrpPipeline.Wait(); err != nil {
		hadErrors = true
		if len(errOutput) == 0 {
			errOutput = append(errOutput, err.Error())
		}
	}

	return &Result{
		Output:      output,
		Errors:      errOutput,
		Warnings:    warnings,
		Verbose:     verbose,
		Debug:       debug,
		Progress:    progress,
		Information: information,
		HadErrors:   hadErrors,
	}, nil
}
