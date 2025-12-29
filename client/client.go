// Package client provides a high-level API for PowerShell Remoting over WSMan.
package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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

	transport     *transport.HTTPTransport
	wsman         *wsman.Client
	pool          *powershell.RunspacePool
	psrpPool      *runspace.Pool
	psrpTransport *powershell.WSManTransport
	poolID        uuid.UUID
	connected     bool
	closed        bool
	messageID     uint64 // Tracks PSRP message ObjectID sequence
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

	return &Client{
		hostname:  hostname,
		config:    cfg,
		endpoint:  endpoint,
		transport: tr,
		wsman:     wsman.NewClient(endpoint, tr),
	}, nil
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

	// 1. Setup PSRP Pool logic EARLY
	// Create unconfigured transport first so we can create PSRP pool
	c.psrpTransport = powershell.NewWSManTransport(nil, "", "")
	c.psrpTransport.SetContext(ctx)

	// Create go-psrpcore Pool using our (currently unconfigured) transport
	c.poolID = uuid.New()
	c.psrpPool = runspace.New(c.psrpTransport, c.poolID)

	// Get the PSRP handshake fragments to embed in creationXml
	frags, err := c.psrpPool.GetHandshakeFragments()
	if err != nil {
		return fmt.Errorf("get handshake fragments: %w", err)
	}
	creationXML := base64.StdEncoding.EncodeToString(frags)

	// 2. Create WSMan shell with creationXml
	// This performs the PSRP handshake (SessionCapability + InitRunspacePool)
	c.pool = powershell.NewRunspacePool(c.wsman)
	if err := c.pool.Open(ctx, creationXML); err != nil {
		return fmt.Errorf("open wsman shell: %w", err)
	}

	// 3. Open the PSRP pool
	c.psrpPool.SkipHandshakeSend = true
	if err := c.psrpPool.Open(ctx); err != nil {
		_ = c.pool.Close(ctx)
		return fmt.Errorf("open psrp pool: %w", err)
	}

	// 4. Drain Shell Output (RunspacePoolState) to ensure pool is ready
	// This is critical: if we don't consume the initial Opened state,
	// subsequent pipeline execution might stall or timeout.
	// We use a short timeout for this initial drain
	drainCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Perform one Receive on the Shell (empty command ID)
	// Drain result is discarded - we just need to consume the state message
	_, _ = c.wsman.Receive(drainCtx, c.pool.ShellID(), "")

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

	if c.pool != nil && c.connected {
		if err := c.pool.Close(ctx); err != nil {
			return fmt.Errorf("close runspace pool: %w", err)
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
	pool := c.pool
	wsman := c.wsman
	c.mu.Unlock()

	// Create a go-psrpcore pipeline for this execution
	// Mimic pypsrp behavior: wrap command in Invoke-Expression and pipe to Out-String
	// This ensures output formatting and execution context match the working client
	// Create a go-psrpcore pipeline for this execution
	// We use the simple CreatePipeline which defaults to IsScript=true
	// This generates <Cmd>script</Cmd><IsScript>true</IsScript>
	psrpPipeline, err := psrpPool.CreatePipeline(script)
	if err != nil {
		return nil, fmt.Errorf("create pipeline: %w", err)
	}

	// Get the CreatePipeline fragment data to embed in WSMan Command Arguments
	// This is the key difference from before - pypsrp sends CreatePipeline in Command Args
	// We use the new GetCreatePipelineDataWithID to ensure ObjectID continuity.
	// We use the new GetCreatePipelineDataWithID to ensure ObjectID continuity.
	c.messageID++
	createPipelineData, err := psrpPipeline.GetCreatePipelineDataWithID(c.messageID)
	if err != nil {
		return nil, fmt.Errorf("get create pipeline data: %w", err)
	}

	// Create WSMan Command with:
	// - CommandID = go-psrpcore Pipeline ID (so response routing works)
	// - Arguments = CreatePipeline fragment (base64 encoded)
	pipelineID := strings.ToUpper(psrpPipeline.ID().String())
	payloadB64 := base64.StdEncoding.EncodeToString(createPipelineData)

	wsmanPipeline, err := pool.CreatePipelineWithArgs(ctx, pipelineID, payloadB64)
	if err != nil {
		return nil, fmt.Errorf("create wsman command: %w", err)
	}
	defer wsmanPipeline.Close(ctx) // Clean up WSMan command when done

	// Configure the transport for this specific command
	c.psrpTransport.Configure(wsman, pool.ShellID(), wsmanPipeline.CommandID())

	// Tell the pipeline to skip sending CreatePipeline - it was already sent in Command Args
	psrpPipeline.SkipInvokeSend()

	// Invoke the pipeline (this now just transitions state, no network send)
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
