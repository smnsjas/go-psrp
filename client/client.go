// Package client provides a high-level API for PowerShell Remoting over WSMan.
package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smnsjas/go-psrp/powershell"
	"github.com/smnsjas/go-psrp/wsman"
	"github.com/smnsjas/go-psrp/wsman/auth"
	"github.com/smnsjas/go-psrp/wsman/transport"
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

	transport *transport.HTTPTransport
	wsman     *wsman.Client
	pool      *powershell.RunspacePool
	connected bool
	closed    bool
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

	// Create runspace pool wrapper
	c.pool = powershell.NewRunspacePool(c.wsman)
	if err := c.pool.Open(ctx); err != nil {
		return fmt.Errorf("open runspace pool: %w", err)
	}

	c.connected = true
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
type Result struct {
	// Output contains the serialized output objects (CLIXML format).
	Output []byte

	// Errors contains any error records returned.
	Errors []byte

	// HadErrors indicates if any errors occurred during execution.
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
	pool := c.pool
	c.mu.Unlock()

	// Create a pipeline for this execution
	pipeline, err := pool.CreatePipeline(ctx)
	if err != nil {
		return nil, fmt.Errorf("create pipeline: %w", err)
	}
	defer pipeline.Close(ctx)

	// Get the io.ReadWriter adapter
	adapter := pipeline.GetAdapter()
	adapter.SetContext(ctx)

	// For now, we return a placeholder result
	// Full go-psrpcore integration requires sending/receiving PSRP fragments
	// which will be implemented in the integration phase
	result := &Result{
		Output:    []byte(script), // Placeholder
		HadErrors: false,
	}

	return result, nil
}
