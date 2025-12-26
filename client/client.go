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
	"github.com/smnsjas/go-psrpcore/runspace"
)

// AuthType specifies the authentication mechanism.
type AuthType int

const (
	// AuthBasic uses HTTP Basic authentication.
	AuthBasic AuthType = iota
	// AuthNTLM uses NTLM authentication.
	AuthNTLM
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

	// AuthType specifies the authentication type (Basic or NTLM).
	AuthType AuthType

	// Username for authentication.
	Username string

	// Password for authentication.
	Password string

	// Domain for NTLM authentication.
	Domain string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:     5985,
		UseTLS:   false,
		Timeout:  60 * time.Second,
		AuthType: AuthBasic,
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Username == "" {
		return errors.New("username is required")
	}
	if c.Password == "" {
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
	case AuthNTLM:
		authenticator = auth.NewNTLMAuth(creds)
	default:
		authenticator = auth.NewBasicAuth(creds)
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
	creationXml := base64.StdEncoding.EncodeToString(frags)

	// 2. Create WSMan shell with creationXml
	// This performs the PSRP handshake (SessionCapability + InitRunspacePool)
	c.pool = powershell.NewRunspacePool(c.wsman)
	if err := c.pool.Open(ctx, creationXml); err != nil {
		return fmt.Errorf("open wsman shell: %w", err)
	}

	// 3. Open the PSRP pool (Skip handshake since it was handled in creationXml)
	// We set SkipHandshakeSend because we already sent the handshake in creationXml
	c.psrpPool.SkipHandshakeSend = true
	if err := c.psrpPool.Open(ctx); err != nil {
		_ = c.pool.Close(ctx) // Best-effort cleanup
		return fmt.Errorf("open psrp pool: %w", err)
	}

	c.connected = true

	// Initialize messageID counter.
	// We assume Session Capability Exchange (ID=1) and InitRunspacePool (ID=2) are sent during connection.
	// So next ID should be 3.
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
// Currently supports Output and Error streams from the pipeline.
// Note: Warning, Verbose, Debug, and Progress streams require
// go-psrpcore enhancements and are not yet exposed.
type Result struct {
	// Output contains the CLIXML-serialized output objects from the pipeline.
	// Use go-psrpcore/serialization.Deserializer to parse into Go types.
	Output []byte

	// Errors contains CLIXML-serialized ErrorRecord objects.
	// Populated when PowerShell writes to the error stream (non-terminating errors).
	Errors []byte

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
	wrappedScript := fmt.Sprintf("Invoke-Expression -Command \"%s\" | Out-String", script)
	psrpPipeline, err := psrpPool.CreatePipeline(wrappedScript)
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
	fmt.Printf("\n--- DEBUG: CreatePipeline Payload (Base64) ---\n%s\n------------------------------------------------\n", payloadB64)

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

	// Collect output
	var output []byte
	var errors []byte
	var hadErrors bool

	// Read from output channel
	for msg := range psrpPipeline.Output() {
		output = append(output, msg.Data...)
	}

	// Read from error channel
	for msg := range psrpPipeline.Error() {
		errors = append(errors, msg.Data...)
		hadErrors = true
	}

	// Wait for completion
	if err := psrpPipeline.Wait(); err != nil {
		hadErrors = true
		if len(errors) == 0 {
			errors = []byte(err.Error())
		}
	}

	return &Result{
		Output:    output,
		Errors:    errors,
		HadErrors: hadErrors,
	}, nil
}
