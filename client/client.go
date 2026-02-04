// Package client provides a high-level API for PowerShell Remoting over WSMan.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrp/powershell"
	"github.com/smnsjas/go-psrp/wsman"
	"github.com/smnsjas/go-psrp/wsman/auth"
	"github.com/smnsjas/go-psrp/wsman/transport"
	"github.com/smnsjas/go-psrpcore/messages"
	"github.com/smnsjas/go-psrpcore/pipeline"
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

// Transport name string constants (for serialization/logging)
const (
	TransportNameWSMan    = "wsman"
	TransportNameHvSocket = "hvsocket"
	TransportNameUnknown  = "unknown"
)

// String returns a string representation of the transport type.
func (t TransportType) String() string {
	switch t {
	case TransportWSMan:
		return TransportNameWSMan
	case TransportHvSocket:
		return TransportNameHvSocket
	default:
		return TransportNameUnknown
	}
}

// CloseStrategy specifies how the client should be closed.
type CloseStrategy int

const (
	// CloseStrategyGraceful attempts to close the remote session cleanly.
	// It sends PSRP and WSMan close messages.
	CloseStrategyGraceful CloseStrategy = iota

	// CloseStrategyForce closes the client immediately without sending network messages.
	// Use this when the connection is known to be broken or responsiveness is required.
	CloseStrategyForce
)

// ReconnectPolicy configures automatic reconnection behavior.
type ReconnectPolicy struct {
	// Enabled activates automatic reconnection on transient failures.
	Enabled bool

	// MaxAttempts is the maximum number of reconnection attempts.
	// 0 means infinite retries.
	MaxAttempts int

	// InitialDelay is the delay before the first reconnection attempt.
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between reconnection attempts.
	// Delays grow exponentially up to this cap.
	MaxDelay time.Duration

	// Jitter adds randomness to delays to prevent thundering herd.
	// Value between 0.0 (no jitter) and 1.0 (up to 100% jitter).
	Jitter float64
}

// DefaultReconnectPolicy returns a sensible default reconnection policy.
func DefaultReconnectPolicy() ReconnectPolicy {
	return ReconnectPolicy{
		Enabled:      false, // Opt-in
		MaxAttempts:  5,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Jitter:       0.2,
	}
}

// RetryPolicy configures command retry behavior for transient failures.
type RetryPolicy struct {
	// Enabled activates command retry.
	Enabled bool

	// MaxAttempts is the maximum number of attempts including the first one.
	// Example: MaxAttempts=3 means 1 original execution + 2 retries.
	// Default: 3.
	MaxAttempts int

	// InitialDelay is the delay before the first retry.
	// Default: 100ms.
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries (exponential cap).
	// Default: 5s.
	MaxDelay time.Duration

	// Multiplier is the backoff multiplier.
	// Default: 2.0.
	Multiplier float64

	// Jitter adds randomness to backoff delay to prevent thundering herd.
	// Value is a factor (0.0-1.0). Example: 0.1 means ±10% variation.
	// Default: 0.1.
	Jitter float64

	// MaxDuration is the maximum total time for all retry attempts.
	// If set, retries stop when this duration expires regardless of MaxAttempts.
	// Zero means no duration limit.
	// Default: 0 (no limit).
	MaxDuration time.Duration
}

// DefaultRetryPolicy returns a conservative default retry policy.
func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		Enabled:      true,
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1, // 10% jitter to prevent thundering herd
	}
}

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

	// TargetSPN is the Kerberos Service Principal Name (e.g., "HTTP/server.domain.com").
	// If empty, defaults to "HTTP/<hostname>".
	TargetSPN string

	// Transport specifies the transport mechanism (WSMan or HvSocket).
	Transport TransportType

	// VMID is the Hyper-V VM GUID (Required for TransportHvSocket).
	VMID string

	// ConfigurationName is the PowerShell configuration name (e.g., "Microsoft.Exchange").
	// If empty, defaults to "Microsoft.PowerShell".
	ConfigurationName string

	// ResourceURI is the full WSMan resource URI (overrides ConfigurationName).
	// Default: http://schemas.microsoft.com/powershell/Microsoft.PowerShell
	ResourceURI string

	// MaxRunspaces limits the number of concurrent pipeline executions.
	// Default: 1 (safe). Set to > 1 to enable concurrent execution if server supports it.
	// This replaces legacy MaxConcurrentCommands.
	MaxRunspaces int

	// MaxConcurrentCommands is deprecated. Use MaxRunspaces instead.
	MaxConcurrentCommands int

	// MaxQueueSize limits the number of commands waiting for a runspace.
	// If 0, queue is unbounded. If > 0, Execute() returns ErrQueueFull if queue is full.
	MaxQueueSize int

	// KeepAliveInterval specifies the interval for sending PSRP keepalive messages
	// (GET_AVAILABLE_RUNSPACES) to maintain session health and prevent timeouts.
	// If 0, keepalive is disabled.
	KeepAliveInterval time.Duration

	// IdleTimeout specifies the WSMan shell idle timeout as an ISO8601 duration string (e.g., "PT1H").
	// If empty, defaults to "PT30M" (30 minutes).
	// Only applies to WSMan transport.
	IdleTimeout string

	// RunspaceOpenTimeout specifies the maximum time to wait for a runspace to open.
	// If 0, defaults to 60 seconds.
	RunspaceOpenTimeout time.Duration

	// EnableCBT enables Channel Binding Tokens (CBT) for NTLM authentication.
	// When enabled, the client will include a CBT derived from the TLS server
	// certificate in NTLM authentication, protecting against NTLM relay attacks.
	// Requires HTTPS (UseTLS: true). Only applies to NTLM authentication.
	EnableCBT bool

	// Reconnect configures automatic reconnection behavior.
	// If Reconnect.Enabled is true, the client will attempt to reconnect
	// when the pool is broken (e.g., connection lost).
	// This handles pool-level recovery.
	Reconnect ReconnectPolicy

	// Retry configures command-level retry behavior for transient failures.
	// If nil, retry is disabled (default).
	// This handles transient network/transport errors during command execution.
	//
	// IMPORTANT: Retry assumes idempotent commands. Non-idempotent commands
	// Retry assumes idempotent commands. Non-idempotent commands
	// with side effects may execute multiple times if retried.
	Retry *RetryPolicy

	// CircuitBreaker configures the circuit breaker to fail fast when server is down.
	// This prevents resource exhaustion by stopping requests after a threshold of failures.
	CircuitBreaker *CircuitBreakerPolicy

	// ProxyURL is the HTTP/HTTPS proxy server URL (e.g., "http://proxy.corp.com:8080").
	// Special values:
	//   - Empty string (default): uses environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)
	//   - "direct": bypasses proxy entirely, ignoring environment variables
	// Only applies to WSMan transport.
	ProxyURL string
}

// IsHvSocket returns true if the client is using the HvSocket transport.
// It checks both the configuration and the active backend implementation.
func (c *Client) IsHvSocket() bool {
	// Check config first
	if c.config.Transport == TransportHvSocket {
		return true
	}

	// Check backend type if initialized
	// This handles cases where config might be default (WSMan) but backend is explicitly HvSocket
	// (e.g. during certain reconnection or test scenarios)
	if c.backend != nil {
		_, ok := c.backend.(*powershell.HvSocketBackend)
		return ok
	}

	return false
}

// CircuitBreakerPolicy configures the failure threshold and recovery timeout.
type CircuitBreakerPolicy struct {
	// Enabled activates the circuit breaker.
	Enabled bool

	// FailureThreshold is the number of consecutive failures before opening the breaker.
	// Default: 5.
	FailureThreshold int

	// ResetTimeout is the duration to wait before testing the connection (Half-Open).
	// Default: 30s.
	ResetTimeout time.Duration

	// SuccessThreshold is the number of consecutive successes required in Half-Open
	// state before transitioning to Closed. Prevents premature recovery.
	// Default: 1.
	SuccessThreshold int

	// OnStateChange is called when the circuit breaker state changes.
	// Called asynchronously to prevent blocking.
	OnStateChange func(from, to CircuitState)

	// OnOpen is called when the circuit opens (too many failures).
	OnOpen func()

	// OnClose is called when the circuit closes (recovery successful).
	OnClose func()

	// OnHalfOpen is called when the circuit enters half-open state.
	OnHalfOpen func()
}

// DefaultCircuitBreakerPolicy returns sensible defaults.
func DefaultCircuitBreakerPolicy() *CircuitBreakerPolicy {
	return &CircuitBreakerPolicy{
		Enabled:          true,
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
		SuccessThreshold: 1, // Single success by default (backward compatible)
	}
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:                  5985,
		UseTLS:                false,
		Timeout:               120 * time.Second,
		AuthType:              AuthNegotiate, // Kerberos preferred, NTLM fallback
		MaxRunspaces:          1,             // Default to safe serial execution
		MaxConcurrentCommands: 1,             // Deprecated
		MaxQueueSize:          -1,            // Unbounded by default
		RunspaceOpenTimeout:   60 * time.Second,
		Reconnect:             DefaultReconnectPolicy(),
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

func encodePowerShellScript(script string) string {
	u16 := utf16.Encode([]rune(script))
	buf := make([]byte, len(u16)*2)
	for i, u := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// Client is a high-level PSRP client for executing PowerShell commands.
type Client struct {
	mu sync.Mutex

	hostname string
	config   Config
	endpoint string

	transport *transport.HTTPTransport
	// wsman is the underlying WSMan client (for WSMan transport)
	wsman *wsman.Client

	// Message fragmentation
	fragmentBuffer bytes.Buffer

	// backend is the PSRP transport backend (WSMan or HvSocket).
	backend powershell.RunspaceBackend

	// backendFactory is an internal hook for testing to inject a mock backend.
	backendFactory func() (powershell.RunspaceBackend, error)

	// psrpPool is the PSRP RunspacePool state machine.
	// psrpPool is the PSRP RunspacePool state machine.
	psrpPool  *runspace.Pool
	poolID    uuid.UUID
	connected bool
	closed    bool
	callID    *callIDManager // Manages atomic PSRP message IDs

	// Concurrency control
	semaphore *poolSemaphore // Limits concurrent command execution
	cmdMu     sync.Mutex     // Serializes command creation (NTLM auth requires this)

	// Logging
	slogLogger *slog.Logger

	// File-based recovery state
	outputFiles map[string]string // Maps PipelineID to remote file path

	// Keepalive management
	keepAliveDone chan struct{}
	keepAliveWg   sync.WaitGroup

	// Automatic reconnection
	reconnectMgr *reconnectManager

	// Circuit Breaker (Fail Fast)
	circuitBreaker *CircuitBreaker

	// Security logging (NIST SP 800-92)
	securityLogger *SecurityLogger
}

// SessionState represents the serialized state of a client session
// needed for persistence and reconnection.
type SessionState struct {
	Transport   string   `json:"transport"`              // "wsman" or "hvsocket"
	PoolID      string   `json:"pool_uuid"`              // RunspacePool UUID
	SessionID   string   `json:"session_id"`             // PSRP Session ID (often same as PoolID)
	MessageID   int64    `json:"message_id"`             // Last used message ID
	RunspaceID  string   `json:"runspace_id,omitempty"`  // Connected Runspace ID (if any)
	PipelineIDs []string `json:"pipeline_ids,omitempty"` // Active pipeline IDs

	// WSMan specific
	ShellID string `json:"shell_id,omitempty"`

	// HvSocket specific
	VMID        string            `json:"vm_id,omitempty"`
	ServiceID   string            `json:"service_id,omitempty"`
	OutputPaths map[string]string `json:"output_paths,omitempty"` // HvSocket file recovery paths
}

// SetSlogLogger sets the structured logger for the client and underlying components.
func (c *Client) SetSlogLogger(logger *slog.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slogLogger = logger.With("component", "client")

	// Propagate to pool if already exists
	if c.psrpPool != nil {
		// Ignore error - pool may already be opened, logger will just not be set
		_ = c.psrpPool.SetSlogLogger(logger) //nolint:errcheck // Best-effort logging config
	}
}

// logf logs a debug message if a logger is configured.
func (c *Client) logf(format string, v ...interface{}) {
	c.mu.Lock()
	logger := c.slogLogger
	c.mu.Unlock()

	if logger != nil {
		logger.Debug(fmt.Sprintf(format, v...))
	}
}

// ensureLogger initializes the logger from environment variables if not already set.
func (c *Client) ensureLogger() {
	if c.slogLogger != nil {
		return
	}

	var level slog.Level
	envLevel := os.Getenv("PSRP_LOG_LEVEL")
	envDebug := os.Getenv("PSRP_DEBUG")

	if envLevel != "" {
		switch strings.ToLower(envLevel) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			// Invalid level, default to debug if debug flag is set, else ignore
			if envDebug != "" {
				level = slog.LevelDebug
			} else {
				return
			}
		}
	} else if envDebug != "" {
		level = slog.LevelDebug
	} else {
		return
	}

	// Use default logger if already configured (respects -quiet, -logfile, etc.)
	// Only create fallback if default has no handler configured
	defaultLogger := slog.Default()
	if defaultLogger.Enabled(context.Background(), level) {
		c.slogLogger = defaultLogger
	} else {
		// Fallback: create minimal stderr logger (for library consumers without CLI)
		c.slogLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))
	}
}

// logfLocked logs a debug message assuming the client lock is already held.
func (c *Client) logfLocked(format string, v ...interface{}) {
	if c.slogLogger != nil {
		c.slogLogger.Debug(fmt.Sprintf(format, v...))
	}
}

// logInfo logs an informational message (normal operations).
func (c *Client) logInfo(format string, v ...interface{}) {
	c.mu.Lock()
	logger := c.slogLogger
	c.mu.Unlock()

	if logger != nil {
		logger.Info(fmt.Sprintf(format, v...))
	}
}

// logInfoLocked logs an informational message assuming the lock is already held.
func (c *Client) logInfoLocked(format string, v ...interface{}) {
	if c.slogLogger != nil {
		c.slogLogger.Info(fmt.Sprintf(format, v...))
	}
}

// logWarn logs a warning message (potential issues, recoverable).
func (c *Client) logWarn(format string, v ...interface{}) {
	c.mu.Lock()
	logger := c.slogLogger
	c.mu.Unlock()

	if logger != nil {
		logger.Warn(fmt.Sprintf(format, v...))
	}
}

// logError logs an error message (failures that affect function).
func (c *Client) logError(format string, v ...interface{}) {
	c.mu.Lock()
	logger := c.slogLogger
	c.mu.Unlock()

	if logger != nil {
		logger.Error(fmt.Sprintf(format, v...))
	}
}

// logSecurityEvent logs a security event with the given event type and details.
// This is used by file transfer operations for security audit logging.
func (c *Client) logSecurityEvent(eventType string, details map[string]interface{}) {
	if c.securityLogger != nil {
		c.securityLogger.LogEvent("file_transfer", eventType, SeverityInfo, OutcomeSuccess, details)
	}
}

// isPoolBrokenError checks if an error indicates the pool is broken.
func (c *Client) isPoolBrokenError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Check for runspace pool broken error patterns
	brokenPatterns := []string{
		"runspace pool broken",
		"runspace pool is broken",
		"pool broken",
		"connection was aborted",
		"wsarecv:",
		"wsasend:",
	}

	for _, pattern := range brokenPatterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}

	return false
}

// waitForRecovery waits for the connection to recover after a pool broken error.
// It polls the Health() status waiting for it to return to Healthy or Degraded.
// Returns true if recovery succeeded, false on timeout.
func (c *Client) waitForRecovery(ctx context.Context, timeout time.Duration) bool {
	c.logInfo("Waiting for connection recovery (timeout: %v)...", timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			health := c.Health()
			c.logf("Recovery check: Health=%s", health)

			if health == HealthHealthy || health == HealthDegraded {
				c.logInfo("Connection recovered! Health=%s", health)
				return true
			}

			if time.Now().After(deadline) {
				c.logWarn("Recovery timeout: Health=%s", health)
				return false
			}
		}
	}
}

// sanitizeScriptForLogging truncates and sanitizes scripts for safe logging.
// It prevents accidental credential exposure in logs by truncating long scripts
// and removing potentially sensitive content.
func sanitizeScriptForLogging(script string) string {
	const maxLen = 100

	// Check for sensitive patterns first (applies to all scripts)
	if containsSensitivePattern(script) {
		return "[script contains sensitive data - not logged]"
	}

	// If script is short enough, return as-is (already checked for sensitive patterns)
	if len(script) <= maxLen {
		return script
	}

	// Long scripts are truncated
	return script[:maxLen] + "... [truncated]"
}

// containsSensitivePattern checks if a string contains common patterns
// that might indicate sensitive data like passwords or credentials.
func containsSensitivePattern(s string) bool {
	// Convert to lowercase for case-insensitive matching
	lower := strings.ToLower(s)

	// Common patterns that might indicate credentials
	sensitivePatterns := []string{
		"password",
		"credential",
		"secret",
		"apikey",
		"api_key",
		"access_token",
		"accesstoken",
		"-password",
		"-credential",
		"convertto-securestring",
		"pscredential",
		"get-credential",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ReconnectSession connects to an existing disconnected session using the provided state.
// This is the transport-agnostic version of Reconnect.
func (c *Client) ReconnectSession(ctx context.Context, state *SessionState) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Restore client state
	if state.PoolID != "" {
		if id, err := uuid.Parse(state.PoolID); err == nil {
			c.poolID = id
		}
	}
	// Restore MessageID sequence
	if state.MessageID > 0 {
		c.callID.Set(state.MessageID)
	}

	// Restore OutputPaths for file-based recovery
	if len(state.OutputPaths) > 0 {
		c.outputFiles = state.OutputPaths
	} else {
		c.outputFiles = make(map[string]string)
	}

	// 2. Initialize Backend based on Transport
	c.logInfoLocked("ReconnectSession: Restoring transport %s", state.Transport)
	switch state.Transport {
	case TransportNameHvSocket:
		// Update config to match state
		c.config.Transport = TransportHvSocket

		vmIDStr := c.config.VMID
		if vmIDStr == "" {
			vmIDStr = state.VMID
			c.config.VMID = vmIDStr // Sync config
		}
		if vmIDStr == "" {
			return fmt.Errorf("missing vmid in both config and state")
		}
		vmID, err := uuid.Parse(vmIDStr)
		if err != nil {
			return fmt.Errorf("parse vmid: %w", err)
		}

		serviceID := c.config.ConfigurationName
		if serviceID == "" {
			serviceID = state.ServiceID
			c.config.ConfigurationName = serviceID // Sync config
		}

		backend := powershell.NewHvSocketBackend(
			vmID,
			c.config.Domain,
			c.config.Username,
			c.config.Password,
			serviceID,
			c.poolID,
		)
		c.backend = backend

		// Connect backend to establish transport
		if err := backend.Connect(ctx); err != nil {
			return fmt.Errorf("connect socket: %w", err)
		}

		// initialize PSRP pool if needed
		if c.psrpPool == nil {
			transport := backend.Transport()
			c.psrpPool = runspace.New(transport, c.poolID)
			// Hook up security logging from protocol layer
			c.psrpPool.SetSecurityEventCallback(func(event string, details map[string]any) {
				if c.securityLogger != nil {
					subtype, ok := details["subtype"].(string)
					if !ok {
						subtype = "unknown"
					}
					outcome, ok := details["outcome"].(string)
					if !ok {
						outcome = "unknown"
					}
					severity := SeverityInfo
					if outcome == "failure" {
						severity = SeverityError
					}
					c.securityLogger.LogEvent(event, subtype, severity, outcome, details)
				}
			})
			c.ensureLogger()
			if c.slogLogger != nil {
				_ = c.psrpPool.SetSlogLogger(c.slogLogger) //nolint:errcheck // Best-effort logging config
			}
		}

		// Sync message ID (critical for determining next PSRP message ID)
		// #nosec G115 -- callID is always positive, starts at 0
		c.psrpPool.SetMessageID(uint64(c.callID.Current()))

		// Check if we are doing file-based recovery (OutputPaths present)
		// If so, we can't Reattach (persistence unsupported), so we Start New Session (Open).
		if len(state.OutputPaths) > 0 {
			// Start fresh session to read files
			// Note: pool.Open sends RUNSPACEPOOL_INIT
			if err := c.psrpPool.Open(ctx); err != nil {
				return fmt.Errorf("open new session for recovery: %w", err)
			}
		} else {
			// Detailed Reattach (performs PSRP handshake via pool.Connect)
			if err := backend.Reattach(ctx, c.psrpPool, ""); err != nil {
				return fmt.Errorf("backend reattach: %w", err)
			}
		}

		c.connected = true
		if c.callID == nil {
			c.callID = newCallIDManager()
		}

		if c.semaphore == nil {
			maxRunspaces := c.config.MaxRunspaces
			if maxRunspaces == 0 && c.config.MaxConcurrentCommands > 0 {
				maxRunspaces = c.config.MaxConcurrentCommands
			}
			if maxRunspaces <= 0 {
				maxRunspaces = 1 // Default safe
			}
			c.semaphore = newPoolSemaphore(maxRunspaces, c.config.MaxQueueSize, c.config.Timeout)
		}

		return nil
	case "wsman", "": // Default to WSMan
		if c.wsman == nil {
			return fmt.Errorf("wsman client not initialized")
		}
		wsmanBackend := powershell.NewWSManBackend(c.wsman, powershell.NewWSManTransport(nil, nil, ""))
		wsmanBackend.SetResourceURI(c.buildResourceURI())
		c.backend = wsmanBackend

		// Use the WSMan-specific Reconnect logic via Reattach
		// We need to re-implement the core logic of Reconnect here because calling
		// c.Reconnect() would deadlock (it locks mutex).

		// Reattach logic adapted from Reconnect:
		if c.psrpPool == nil {
			transport := c.backend.Transport()
			if t, ok := transport.(*powershell.WSManTransport); ok {
				t.SetContext(ctx)
			}
			c.psrpPool = runspace.New(transport, c.poolID)
			// Hook up security logging from protocol layer
			c.psrpPool.SetSecurityEventCallback(func(event string, details map[string]any) {
				if c.securityLogger != nil {
					subtype, ok := details["subtype"].(string)
					if !ok {
						subtype = "unknown"
					}
					outcome, ok := details["outcome"].(string)
					if !ok {
						outcome = "unknown"
					}
					severity := SeverityInfo
					if outcome == "failure" {
						severity = SeverityError
					}
					c.securityLogger.LogEvent(event, subtype, severity, outcome, details)
				}
			})
			c.ensureLogger()
			if c.slogLogger != nil {
				_ = c.psrpPool.SetSlogLogger(c.slogLogger) //nolint:errcheck // Best-effort logging config
			}
		}

		if wsmanBackend, ok := c.backend.(*powershell.WSManBackend); ok {
			if err := wsmanBackend.Reattach(ctx, c.psrpPool, state.ShellID); err != nil {
				return fmt.Errorf("backend reattach: %w", err)
			}
		}

		c.connected = true

		// Initialize semaphore if not already done
		if c.semaphore == nil {
			maxRunspaces := c.config.MaxRunspaces
			if maxRunspaces == 0 && c.config.MaxConcurrentCommands > 0 {
				maxRunspaces = c.config.MaxConcurrentCommands
			}
			if maxRunspaces <= 0 {
				maxRunspaces = 1 // Default safe
			}
			c.semaphore = newPoolSemaphore(maxRunspaces, c.config.MaxQueueSize, c.config.Timeout)
		}

		// Ensure pool uses the correct message ID
		// #nosec G115 -- callID is always positive, starts at 0
		c.psrpPool.SetMessageID(uint64(c.callID.Current()))

		return nil
	default:
		return fmt.Errorf("unknown transport type: %s", state.Transport)
	}
}

// SaveState saves the current session state to a file.
func (c *Client) SaveState(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected && !c.closed {
		// If we are just initialized but disconnected, we might still want to save state
		// if we have enough info (e.g. ShellID/PoolID from previous session)
	}

	state := &SessionState{
		PoolID:      c.poolID.String(),
		SessionID:   c.poolID.String(), // Typically same as PoolID
		MessageID:   c.callID.Current(),
		RunspaceID:  "",            // We don't track explicit Runspace ID yet, usually implied by Pool
		PipelineIDs: []string{},    // pipelines are tracked in runspace pool
		OutputPaths: c.outputFiles, // Save file recovery paths
	}

	// Transport specific info
	if c.config.Transport == TransportHvSocket {
		state.Transport = TransportNameHvSocket
		state.VMID = c.config.VMID
		state.ServiceID = c.config.ConfigurationName // Using config name as ServiceID proxy/context
	} else {
		state.Transport = TransportNameWSMan
		if c.backend != nil {
			state.ShellID = c.backend.ShellID()
		}
	}

	// Get active pipelines from PSRP pool if available
	if c.psrpPool != nil {
		ids := c.psrpPool.GetActivePipelineIDs()
		for _, id := range ids {
			state.PipelineIDs = append(state.PipelineIDs, id.String())
		}
	}

	// Serialize to JSON
	// We use json.MarshalIndent for readability
	// We write carefully to file

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	// Write to file with restricted permissions (0600)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}

	return nil
}

// LoadState loads a session state from a file.
func LoadState(path string) (*SessionState, error) {
	// Security: Clean the path to prevent basic traversal weirdness, though checking '..' is complex
	// without a root directory constraint. Here we just normalize.
	path = filepath.Clean(path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	return &state, nil
}

// New creates a new PSRP client.
func New(hostname string, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Build endpoint URL
	var endpoint string
	if strings.HasPrefix(hostname, "http://") || strings.HasPrefix(hostname, "https://") {
		endpoint = hostname
	} else {
		scheme := "http"
		if cfg.UseTLS {
			scheme = "https"
		}
		endpoint = fmt.Sprintf("%s://%s:%d/wsman", scheme, hostname, cfg.Port)
	}

	// Create transport with auth
	tr := transport.NewHTTPTransport(
		transport.WithTimeout(cfg.Timeout),
		transport.WithInsecureSkipVerify(cfg.InsecureSkipVerify),
		transport.WithProxy(cfg.ProxyURL),
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
		targetSPN := cfg.TargetSPN
		if targetSPN == "" {
			// WinRM uses WSMAN/ SPN, not HTTP/
			targetSPN = fmt.Sprintf("WSMAN/%s", hostname)
		}
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
			authenticator = auth.NewNTLMAuth(creds, auth.WithCBT(cfg.EnableCBT))
		} else {
			authenticator = auth.NewNegotiateAuth(provider)
		}
	case AuthNTLM:
		authenticator = auth.NewNTLMAuth(creds, auth.WithCBT(cfg.EnableCBT))
	case AuthKerberos:
		// Kerberos only - no fallback
		targetSPN := cfg.TargetSPN
		if targetSPN == "" {
			// WinRM uses WSMAN/ SPN, not HTTP/
			targetSPN = fmt.Sprintf("WSMAN/%s", hostname)
		}
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
		authenticator = auth.NewNTLMAuth(creds, auth.WithCBT(cfg.EnableCBT))
	}

	// Wrap transport with auth
	tr.Client().Transport = authenticator.Transport(tr.Client().Transport)

	switch cfg.Transport {
	case TransportHvSocket:
		// Convert String VMID to UUID
		if _, err := uuid.Parse(cfg.VMID); err != nil {
			return nil, fmt.Errorf("invalid vmid: %w", err)
		}

		// For HvSocket, we don't need the HTTP transport or WSMan client.
		return &Client{
			hostname: hostname,
			config:   cfg,
			endpoint: "",
			// semaphore initialized in Connect/Reconnect to allow state recovery adjustment if needed?
			// But Execute checks for it. Better initialize here if possible, or lazy init.
			// Let's initialize here with safe defaults.
			semaphore:      newPoolSemaphore(cfg.MaxRunspaces, cfg.MaxQueueSize, cfg.Timeout),
			outputFiles:    make(map[string]string),
			callID:         newCallIDManager(),
			circuitBreaker: NewCircuitBreaker(cfg.CircuitBreaker),
		}, nil

	default: // WSMan
		// ... existing WSMan setup ...
		return &Client{
			hostname:       hostname,
			config:         cfg,
			endpoint:       endpoint,
			transport:      tr,
			wsman:          wsman.NewClient(endpoint, tr),
			semaphore:      newPoolSemaphore(cfg.MaxRunspaces, cfg.MaxQueueSize, cfg.Timeout),
			outputFiles:    make(map[string]string),
			callID:         newCallIDManager(),
			circuitBreaker: NewCircuitBreaker(cfg.CircuitBreaker),
		}, nil
	}
}

// CloneForWorker creates a lightweight clone of the client for parallel operations.
// The cloned client shares the configuration and targets the SAME remote Shell,
// but uses a dedicated Transport (and thus a dedicated Authentication Context/TCP connection).
// This is critical for HTTP-based protocols (like Kerberos over HTTP) where security contexts
// are often bound to the connection.
// CreateWorker creates a new independent client for parallel operations.
// This ensures each worker runs in its own RunspacePool with its own Authentication Context,
// avoiding WinRM "Shared Shell" errors and Auth Loop race conditions.
func (c *Client) CreateWorker() (*Client, error) {
	return New(c.hostname, c.config)
}

// CloseIdleConnections closes any idle connections in the underlying transport.
func (c *Client) CloseIdleConnections() {
	c.mu.Lock()
	backend := c.backend
	c.mu.Unlock()

	if backend == nil {
		return
	}

	// Dynamic check for CloseIdleConnections support in backend
	type idleCloser interface {
		CloseIdleConnections()
	}

	if closer, ok := backend.(idleCloser); ok {
		closer.CloseIdleConnections()
	}
}

// Endpoint returns the WinRM endpoint URL.
func (c *Client) Endpoint() string {
	return c.endpoint
}

// Connect establishes a connection to the remote server.
func (c *Client) Connect(ctx context.Context) error {
	// Wrap connection logic in Circuit Breaker
	// If the circuit is open, this will return ErrCircuitOpen immediately.
	// We use c.circuitBreaker if it exists (it should, initialized in New).
	// But check for nil just in case (e.g. malformed test setup).
	if c.circuitBreaker == nil {
		return c.connectInternal(ctx)
	}

	return c.circuitBreaker.Execute(func() error {
		return c.connectInternal(ctx)
	})
}

// connectInternal performs the actual connection logic.
func (c *Client) connectInternal(ctx context.Context) error {
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

	// Ensure logger is initialized early
	c.ensureLogger()
	c.logInfoLocked("Initializing new session with PoolID %s", c.poolID)

	// Initialize security logger (NIST SP 800-92)
	target := c.hostname
	if c.config.Transport == TransportHvSocket {
		target = "hvsocket://" + c.config.VMID
	}
	c.securityLogger = NewSecurityLogger(c.slogLogger, c.config.Username, target)
	c.securityLogger.LogConnection(SubtypeConnEstablished, OutcomeSuccess, SeverityInfo, map[string]any{
		"pool_id":   c.poolID.String(),
		"transport": c.config.Transport.String(),
	})

	if c.backendFactory != nil {
		var err error
		c.backend, err = c.backendFactory()
		if err != nil {
			return fmt.Errorf("create backend from factory: %w", err)
		}
	} else {
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
		case TransportWSMan:
			// Ensure wsman client is set (it should be from New)
			if c.wsman == nil {
				return fmt.Errorf("wsman client not initialized")
			}
			// Create WSMan transport
			wTransport := powershell.NewWSManTransport(c.wsman, nil, "") // EPR will be set by Init

			// Create backend
			wsmanBackend := powershell.NewWSManBackend(c.wsman, wTransport)
			wsmanBackend.SetResourceURI(c.buildResourceURI())

			// Configure Idle Timeout if set
			if c.config.IdleTimeout != "" {
				wsmanBackend.SetIdleTimeout(c.config.IdleTimeout)
			}

			c.backend = wsmanBackend
		default: // WSMan
			// Ensure wsman client is set (it should be from New)
			if c.wsman == nil {
				return fmt.Errorf("wsman client not initialized")
			}
			backend := powershell.NewWSManBackend(c.wsman, powershell.NewWSManTransport(nil, nil, ""))
			if c.config.IdleTimeout != "" {
				backend.SetIdleTimeout(c.config.IdleTimeout)
			}
			c.backend = backend
		}
	}
	c.logInfoLocked("Connecting backend...")

	// 2. Connect Backend (Prepare Transport)
	if err := c.backend.Connect(ctx); err != nil {
		c.securityLogger.LogConnection(SubtypeConnFailed, OutcomeFailure, SeverityError, map[string]any{
			"error": err.Error(),
			"stage": "backend_connect",
		})
		return fmt.Errorf("connect backend: %w", err)
	}

	// 3. Get Transport
	transport := c.backend.Transport()

	// Set Context on transport if it supports it (WSManTransport does)
	// We need type assertion
	if t, ok := transport.(*powershell.WSManTransport); ok {
		t.SetContext(ctx)
	}

	// 4. Create PSRP Pool
	// We use the ID we generated earlier
	c.psrpPool = runspace.New(transport, c.poolID)

	// Propagate logger if configured
	if c.slogLogger != nil {
		_ = c.psrpPool.SetSlogLogger(c.slogLogger) //nolint:errcheck // Best-effort logging config
	} else if os.Getenv("PSRP_DEBUG") != "" || os.Getenv("PSRP_LOG_LEVEL") != "" {
		// Enable debug logging if PSRP_DEBUG is set (legacy fallback) or PSRP_LOG_LEVEL is set
		c.psrpPool.EnableDebugLogging()
	}

	// Configure pool size for concurrent execution
	// Per MS-PSRP spec, each runspace can only execute one pipeline at a time.
	// To run multiple pipelines concurrently, we need a pool with multiple runspaces.
	maxRunspaces := c.config.MaxRunspaces
	if maxRunspaces == 0 && c.config.MaxConcurrentCommands > 0 {
		maxRunspaces = c.config.MaxConcurrentCommands
	}
	if maxRunspaces <= 0 {
		maxRunspaces = 1
	}

	// Pool configuration errors can only occur if called after Open(), which hasn't happened yet
	_ = c.psrpPool.SetMinRunspaces(1)            //nolint:errcheck // Called before Open()
	_ = c.psrpPool.SetMaxRunspaces(maxRunspaces) //nolint:errcheck // Called before Open()
	c.logInfoLocked("Configured RunspacePool with MaxRunspaces=%d", maxRunspaces)

	// Ensure semaphore matches
	// If reconnecting, we might already have one. If connecting fresh, we override.
	// Or we just update existing one? semaphore struct is immutable-ish (channels).
	// Safest is to recreate if limits changed, but usually config is static.
	if c.semaphore == nil {
		c.semaphore = newPoolSemaphore(maxRunspaces, c.config.MaxQueueSize, c.config.Timeout)
	}

	// 5. Init Backend (Handshake + Shell Creation)
	// This calls pool.Open() internally after ensuring backend-specific setup (like WSMan Shell creation)
	if err := c.backend.Init(ctx, c.psrpPool); err != nil {
		c.securityLogger.LogConnection(SubtypeConnFailed, OutcomeFailure, SeverityError, map[string]any{
			"error": err.Error(),
			"stage": "backend_init",
		})
		return fmt.Errorf("init backend: %w", err)
	}
	// Log successful session establishment
	c.securityLogger.LogSession(SubtypeSessionOpened, OutcomeSuccess, SeverityInfo, map[string]any{
		"pool_id":       c.poolID.String(),
		"max_runspaces": maxRunspaces,
	})

	// 6. Start dispatch loop for shared transports (HvSocket)
	// For WSMan, per-pipeline transports are used instead.
	// SupportsPSRPKeepalive() returns true for HvSocket (shared transport).
	if c.backend.SupportsPSRPKeepalive() {
		c.psrpPool.StartDispatchLoop()

		// Give dispatch loop time to receive RUNSPACE_AVAILABILITY if server sends it
		// After this delay, if no message received, assume full availability
		time.Sleep(250 * time.Millisecond)

		c.psrpPool.InitializeAvailabilityIfNeeded()
	}

	// Note: The pool now properly waits for server handshake response
	// (SESSION_CAPABILITY + RUNSPACEPOOL_STATE) during Open(), so we no longer
	// need to drain here. The old drain logic caused HTTP 500 errors because
	// the messages were already consumed by the pool.

	// Wait for at least 1 runspace to be available before declaring "Connected"
	// This ensures Health() returns Healthy immediately after Connect().
	// With smart detection: If server doesn't send RUNSPACE_AVAILABILITY, we assume
	// full availability after pool opens (250ms grace period above).
	if c.backend.SupportsPSRPKeepalive() {
		waitCtx, waitCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer waitCancel()
		if err := c.psrpPool.WaitForAvailability(waitCtx, 1); err != nil {
			// Timeout is OK - means server initialized availability to MaxRunspaces
			c.logInfo("WaitForAvailability completed: %v", err)
		}
	}

	c.connected = true

	// Initialize messageID counter.
	// WSMan Shell creation sends messages 1 (SESSION_CAPABILITY) and 2 (INIT_RUNSPACEPOOL)
	// via creationXml. We sync the pool's fragmenter so subsequent messages start at 3.
	// Initialize messageID counter.
	// WSMan Shell creation sends messages 1 (SESSION_CAPABILITY) and 2 (INIT_RUNSPACEPOOL)
	// via creationXml. We sync the pool's fragmenter so subsequent messages start at 3.
	c.callID.Set(2)
	c.psrpPool.SetMessageID(2)

	// Initialize semaphore for concurrent command limiting
	// Note: We already initialized it above in Step 4's logic block.
	// But let's ensure it's set just in case logic flow changes.
	if c.semaphore == nil {
		c.semaphore = newPoolSemaphore(maxRunspaces, c.config.MaxQueueSize, c.config.Timeout)
	}

	// Start keepalive loop if configured AND supported by the backend.
	// WSMan uses WS-MAN level keepalive on Receive operations instead.
	if c.config.KeepAliveInterval > 0 && c.backend.SupportsPSRPKeepalive() {
		c.logInfoLocked("Starting keepalive loop (Interval: %v)", c.config.KeepAliveInterval)
		c.startKeepaliveLocked()
	} else if c.config.KeepAliveInterval > 0 {
		c.logInfoLocked("PSRP keepalive disabled for this transport (using WS-MAN level keepalive)")
	} else {
		c.logInfoLocked("Keepalive disabled")
	}

	// Start automatic reconnection manager if enabled
	if c.config.Reconnect.Enabled {
		c.reconnectMgr = newReconnectManager(c, c.config.Reconnect)
		c.reconnectMgr.start()
		c.logInfoLocked("Automatic reconnection enabled (MaxAttempts: %d)", c.config.Reconnect.MaxAttempts)
	}

	return nil
}

// Disconnect disconnects the active session without closing it on the server.
// This is useful for saving state and reconnecting later.

// Close closes the connection to the remote server using the Graceful strategy.
func (c *Client) Close(ctx context.Context) error {
	return c.CloseWithStrategy(ctx, CloseStrategyGraceful)
}

// CloseWithStrategy closes the connection using the specified strategy.
func (c *Client) CloseWithStrategy(ctx context.Context, strategy CloseStrategy) error {
	c.logInfo("CloseWithStrategy called (strategy: %v)", strategy)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true

	// Stop keepalive loop (signal only)
	if c.keepAliveDone != nil {
		close(c.keepAliveDone)
		c.keepAliveDone = nil
	}

	// Stop reconnect manager
	reconnectMgr := c.reconnectMgr
	c.reconnectMgr = nil

	// Read fields needed for cleanup
	pool := c.psrpPool
	backend := c.backend
	connected := c.connected
	c.mu.Unlock()

	// Wait for keepalive goroutine to exit (outside lock)
	c.keepAliveWg.Wait()

	// Stop reconnect manager (outside lock to avoid deadlock)
	if reconnectMgr != nil {
		reconnectMgr.stop()
	}

	// Release all semaphore slots?
	// The semaphore implementation doesn't support "Close", but blocked Acquire calls
	// that respect context will eventually timeout/cancel.
	// Those blocked on the semaphore specifically: we don't have a way to unblock them
	// unless they are checking `c.closed` after acquire, or we close a channel they are watching?
	// Our `Acquire` only watches context.
	// It's acceptable for now.

	if strategy == CloseStrategyForce {
		// For forced close, we just want to ensure local state is cleaned up if possible.
		// We skip network calls.
		// However, we might want to tell the runspace pool implementation we are done?
		// go-psrpcore doesn't expose a "ForceClose" that skips network unless context is cancelled?
		// We can Simulate cancelled context.
		// But better to just skip the calls.
		return nil
	}

	// Graceful Shutdown
	// First close the runspace pool (sends RUNSPACEPOOL_STATE=Closed message)
	if pool != nil {
		_ = pool.Close(ctx)
	}

	// Then close the backend (sends transport-level Close and closes connection)
	if backend != nil && connected {
		if err := backend.Close(ctx); err != nil {
			return fmt.Errorf("close backend: %w", err)
		}
	}

	// Log session closed (NIST SP 800-92)
	c.mu.Lock()
	if c.securityLogger != nil {
		c.securityLogger.LogSession(SubtypeSessionClosed, OutcomeSuccess, SeverityInfo, map[string]any{
			"strategy": strategy,
		})
		c.securityLogger.LogConnection(SubtypeConnClosed, OutcomeSuccess, SeverityInfo, nil)
	}
	c.mu.Unlock()

	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected && !c.closed
}

// State returns the current connection state of the underlying RunspacePool.
func (c *Client) State() runspace.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.psrpPool == nil {
		return runspace.StateBeforeOpen
	}
	return c.psrpPool.State()
}

// HealthStatus represents the high-level health of the client connection.
type HealthStatus string

const (
	HealthHealthy   HealthStatus = "Healthy"
	HealthDegraded  HealthStatus = "Degraded"  // Connected but busy or experiencing issues
	HealthUnhealthy HealthStatus = "Unhealthy" // Disconnected, Broken, or Closed
	HealthUnknown   HealthStatus = "Unknown"   // Initializing or unknown state
)

// Health returns the current high-level health status of the client.
func (c *Client) Health() HealthStatus {
	c.mu.Lock()
	pool := c.psrpPool
	c.mu.Unlock()

	if pool == nil {
		return HealthUnknown
	}

	state := pool.State()
	switch state {
	case runspace.StateOpened:
		// For backends without dispatch loops (WSMan), availability tracking doesn't apply.
		// If the pool is Opened, it's healthy.
		// For backends with dispatch loops (HvSocket), check availability.
		c.mu.Lock()
		backend := c.backend
		c.mu.Unlock()

		if backend != nil && !backend.SupportsPSRPKeepalive() {
			// WSMan: Opened = Healthy (availability not tracked via dispatch loop)
			return HealthHealthy
		}

		// HvSocket: Check availability
		// If AvailableRunspaces > 0, we can accept new commands immediately.
		// If 0, we are busy (Degraded).
		count := pool.AvailableRunspaces()
		if count > 0 {
			return HealthHealthy
		}
		return HealthDegraded
	case runspace.StateBeforeOpen, runspace.StateOpening, runspace.StateConnecting:
		return HealthUnknown
	default: // Closed, Broken, disconnected
		return HealthUnhealthy
	}
}

// RunspaceUtilization returns the current runspace pool utilization statistics.
// Returns (available, total) where:
//   - available: runspaces ready for new pipelines
//   - total: maximum runspaces configured for this pool
//
// For HvSocket backends, availability is tracked via RUNSPACE_AVAILABILITY messages.
// For WSMan backends, availability tracking is not supported (always returns 0, total).
func (c *Client) RunspaceUtilization() (available, total int) {
	c.mu.Lock()
	pool := c.psrpPool
	c.mu.Unlock()

	if pool == nil {
		return 0, 0
	}

	available, total = pool.RunspaceUtilization()
	return available, total
}

// startKeepaliveLocked starts the keepalive goroutine (caller must hold c.mu).
func (c *Client) startKeepaliveLocked() {
	interval := c.config.KeepAliveInterval
	if interval <= 0 {
		return
	}

	if c.keepAliveDone != nil {
		return // Already running
	}

	c.keepAliveDone = make(chan struct{})
	c.keepAliveWg.Add(1)

	// Log must use locked version since we hold the lock
	// But logInfoLocked expects to be called with lock held, which matches.
	// Wait, logInfoLocked just calls slog which is thread safe?
	// Let's check logInfoLocked implementation.
	// It accesses c.slogLogger which is protected by mu?
	// Yes.

	// However, we want to log OUTSIDE the lock to avoid blocking logging?
	// No, we are inside the lock. We should use logInfoLocked.
	// But wait, the original startKeepalive logged "Starting keepalive loop" OUTSIDE the lock.
	// We can log inside.
	c.logInfoLocked("Starting keepalive loop logic (interval: %v)", interval)

	go c.keepaliveLoop(interval)
}

// stopKeepalive stops the keepalive goroutine.
func (c *Client) stopKeepalive() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.keepAliveDone != nil {
		close(c.keepAliveDone)
		c.keepAliveDone = nil
	}
}

// stopKeepaliveAndWait stops the keepalive goroutine and waits for it to exit.
func (c *Client) stopKeepaliveAndWait() {
	c.stopKeepalive()
	c.keepAliveWg.Wait()
}

// keepaliveLoop sends periodic GET_AVAILABLE_RUNSPACES messages.
func (c *Client) keepaliveLoop(interval time.Duration) {
	defer c.keepAliveWg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		// handle stop signal
		c.mu.Lock()
		doneCh := c.keepAliveDone
		pool := c.psrpPool

		c.mu.Unlock()

		if doneCh == nil {
			return
		}

		select {
		case <-doneCh:
			return
		case <-ticker.C:
			// Send Keepalive
			if pool == nil {
				continue
			}

			// We need a context for the send
			// We use a short timeout so we don't block forever
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

			// Send Keepalive (GET_AVAILABLE_RUNSPACES)
			// This maintains the session and ensures connectivity.
			c.logf("Sending Keepalive (GET_AVAILABLE_RUNSPACES)")
			if err := pool.SendGetAvailableRunspaces(ctx); err != nil {
				c.logWarn("Keepalive failed: %v", err)
				// TODO: consider emitting an event or checking if connection is dead
			}
			cancel()
		}
	}
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
	c.logInfo("Execute called: '%s'", sanitizeScriptForLogging(script))

	// Security Logging (Start)
	if c.securityLogger != nil {
		c.securityLogger.LogCommand(SubtypeCommandExecute, OutcomeAttempt, SeverityInfo, map[string]any{
			"script": sanitizeScriptForLogging(script),
		})
	}

	// Determine retry configuration
	var maxAttempts int
	var retryPolicy *RetryPolicy

	if c.config.Retry != nil && c.config.Retry.Enabled {
		// New retry logic
		maxAttempts = c.config.Retry.MaxAttempts
		retryPolicy = c.config.Retry
	} else {
		// Legacy: Use reconnect config for backward compat
		maxAttempts = 1
		if c.config.Reconnect.Enabled && c.config.Reconnect.MaxAttempts > 0 {
			maxAttempts = c.config.Reconnect.MaxAttempts
		}
	}

	var result *Result

	// Wrap execution logic in Circuit Breaker
	operation := func() error {
		var lastErr error
		retryStartTime := time.Now()

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			// Check MaxDuration before each attempt (except first)
			if attempt > 1 && retryPolicy != nil && retryPolicy.MaxDuration > 0 {
				elapsed := time.Since(retryStartTime)
				if elapsed > retryPolicy.MaxDuration {
					c.logError("Execute failed (max duration %v exceeded after %d attempts): %v",
						retryPolicy.MaxDuration, attempt-1, lastErr)
					if c.securityLogger != nil {
						c.securityLogger.LogCommand(SubtypeCommandFailed, OutcomeFailure, SeverityError, map[string]any{
							"error":        lastErr.Error(),
							"attempts":     attempt - 1,
							"max_duration": retryPolicy.MaxDuration.String(),
							"elapsed":      elapsed.String(),
						})
					}
					return fmt.Errorf("retry max duration exceeded after %d attempts: %w", attempt-1, lastErr)
				}
			}

			// Try execute with reconnection handling
			res, err := c.executeWithReconnectHandling(ctx, script)
			if err == nil {
				// Security Logging (Success)
				if c.securityLogger != nil {
					hadErrors := res.HadErrors
					outcome := OutcomeSuccess
					severity := SeverityInfo
					if hadErrors {
						outcome = OutcomeFailure
						severity = SeverityWarning
					}
					c.securityLogger.LogCommand(SubtypeCommandComplete, outcome, severity, map[string]any{
						"had_errors": hadErrors,
						"attempts":   attempt,
					})
				}
				result = res
				return nil // Success
			}

			lastErr = err

			// Check if error is retryable
			// Note: executeWithReconnectHandling already handled pool-level ErrBroken
			if !isRetryableError(err) {
				c.logError("Execute failed (non-recoverable): %v", err)
				// Security Logging (Failure)
				if c.securityLogger != nil {
					c.securityLogger.LogCommand(SubtypeCommandFailed, OutcomeFailure, SeverityError, map[string]any{
						"error":    err.Error(),
						"attempts": attempt,
					})
				}
				return err
			}

			if attempt >= maxAttempts {
				c.logError("Execute failed (max attempts %d reached): %v", maxAttempts, err)
				// Security Logging (Failure - Max Attempts)
				if c.securityLogger != nil {
					c.securityLogger.LogCommand(SubtypeCommandFailed, OutcomeFailure, SeverityError, map[string]any{
						"error":        err.Error(),
						"attempts":     attempt,
						"max_attempts": maxAttempts,
					})
				}
				return err
			}

			// Calculate backoff
			var delay time.Duration
			if retryPolicy != nil {
				delay = calculateRetryBackoff(attempt, retryPolicy)
			} else {
				// Legacy fallback logic
				delay = c.config.Reconnect.InitialDelay
				if delay == 0 {
					delay = 1 * time.Second
				}
				// Exponential backoff for legacy
				for i := 1; i < attempt; i++ {
					delay = time.Duration(float64(delay) * 2)
					if delay > c.config.Reconnect.MaxDelay {
						delay = c.config.Reconnect.MaxDelay
						break
					}
				}
			}

			c.logWarn("Execute attempt %d/%d failed (transient): %v, retrying in %v",
				attempt, maxAttempts, err, delay)

			// Security Logging (Retry)
			if c.securityLogger != nil {
				c.securityLogger.LogEvent("command", "retry", SeverityWarning, OutcomeAttempt, map[string]any{
					"attempt":      attempt,
					"max_attempts": maxAttempts,
					"error":        err.Error(),
					"backoff":      delay.String(),
				})
			}

			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		return lastErr
	}

	var err error
	if c.circuitBreaker != nil {
		err = c.circuitBreaker.Execute(operation)
	} else {
		err = operation()
	}

	return result, err
}

// executeWithReconnectHandling executes command with automatic reconnection handling.
//
// If pool is broken and reconnection is enabled, waits for recovery and retries ONCE.
// This is separate from the command retry loop above.
func (c *Client) executeWithReconnectHandling(ctx context.Context, script string) (*Result, error) {
	// Try execute
	result, err := c.executeOnce(ctx, script)

	// Check if this is a pool broken error
	isPoolBroken := c.isPoolBrokenError(err)

	// If pool broken and reconnection enabled, wait for recovery
	if isPoolBroken && c.config.Reconnect.Enabled {
		c.logWarn("Execute: pool broken, waiting for reconnection...")

		// Security Logging (Reconnection Start)
		if c.securityLogger != nil {
			c.securityLogger.LogEvent(EventReconnection, "start", SeverityWarning, OutcomeAttempt, map[string]any{
				"reason": "pool_broken",
			})
		}

		// Wait for the reconnect manager to recover the connection
		// Note: In legacy implementation this timeout depended on retry attempts
		// Here we use a fixed sensible timeout or Reconnect.MaxDelay * attempts equivalent
		recoveryTimeout := 30 * time.Second // Reasonable default for reconnection

		if recovered := c.waitForRecovery(ctx, recoveryTimeout); recovered {
			c.logInfo("Execute: connection recovered, retrying command")

			// Security Logging (Reconnection Success)
			if c.securityLogger != nil {
				c.securityLogger.LogEvent(EventReconnection, "success", SeverityInfo, OutcomeSuccess, nil)
			}

			// Retry ONCE after reconnection
			return c.executeOnce(ctx, script)
		}

		c.logError("Execute: connection did not recover within timeout")
		return nil, err
	}

	return result, err
}

// executeOnce performs a single command execution attempt including waiting for results.
func (c *Client) executeOnce(ctx context.Context, script string) (*Result, error) {
	streamResult, err := c.ExecuteStream(ctx, script)
	if err != nil {
		return nil, err
	}

	// Wait for results - consume streams into slices
	var (
		output      []interface{}
		errorsList  []interface{}
		warnings    []interface{}
		verbose     []interface{}
		debug       []interface{}
		progress    []interface{}
		information []interface{}
	)

	// Consumer loop
	var wg sync.WaitGroup
	wg.Add(7)

	collect := func(ch <-chan *messages.Message, target *[]interface{}) {
		defer wg.Done()
		for msg := range ch {
			if msg == nil {
				continue
			}
			deser := serialization.NewDeserializer()
			results, err := deser.Deserialize(msg.Data)
			if err != nil {
				continue
			}
			*target = append(*target, results...)
		}
	}

	go collect(streamResult.Output, &output)
	go collect(streamResult.Errors, &errorsList)
	go collect(streamResult.Warnings, &warnings)
	go collect(streamResult.Verbose, &verbose)
	go collect(streamResult.Debug, &debug)
	go collect(streamResult.Progress, &progress)
	go collect(streamResult.Information, &information)

	// Wait for pipeline to finish and streams to close
	runErr := streamResult.Wait()
	wg.Wait()

	// If Wait() returned an error, propagate it for retry handling
	if runErr != nil {
		return nil, runErr
	}

	// Check if there were errors
	hadErrors := len(errorsList) > 0

	return &Result{
		Output:      output,
		Errors:      errorsList,
		Warnings:    warnings,
		Verbose:     verbose,
		Debug:       debug,
		Progress:    progress,
		Information: information,
		HadErrors:   hadErrors,
	}, nil
}

// startPipeline creates, prepares, and invokes a pipeline.
// It returns the pipeline, the transport (for reading output), and a cleanup function.
// Caller is responsible for handling the transport (e.g. starting receive loop) and calling cleanup.
func (c *Client) startPipeline(ctx context.Context, script string) (*pipeline.Pipeline, io.Reader, func(), error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, nil, nil, errors.New("client not connected")
	}
	if c.closed {
		c.mu.Unlock()
		return nil, nil, nil, errors.New("client is closed")
	}
	psrpPool := c.psrpPool
	backend := c.backend
	callID := c.callID
	c.mu.Unlock()

	// DISABLED: Wait for available runspace before creating pipeline
	// This was causing PowerShell Direct (HvSocket) to hang because many servers
	// don't send RUNSPACE_AVAILABILITY messages. The semaphore already limits
	// concurrent execution. Availability tracking is a nice-to-have optimization,
	// not a requirement.
	//
	// TODO: Re-enable with smarter logic:
	// - If server sends RUNSPACE_AVAILABILITY, use it
	// - If not, assume availability=MaxRunspaces
	/*
		if backend != nil && backend.SupportsPSRPKeepalive() {
			waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			if err := psrpPool.WaitForAvailability(waitCtx, 1); err != nil {
				c.logWarn("Runspace availability wait failed: %v (continuing anyway)", err)
				// Non-blocking failure - server might still accept pipeline
			} else {
				available, total := psrpPool.RunspaceUtilization()
				c.logf("Runspace pool: %d available / %d total", available, total)
			}
		}
	*/

	// Create pipeline
	psrpPipeline, err := psrpPool.CreatePipeline(script)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create pipeline: %w", err)
	}

	// Prepare payload
	// #nosec G115 -- callID is always positive, starts at 0
	msgID := uint64(callID.Next())
	createPipelineData, err := psrpPipeline.GetCreatePipelineDataWithID(msgID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get create pipeline data: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(createPipelineData)

	// Prepare backend (retry loop for NTLM)
	var pipelineTransport io.Reader
	var cleanupBackend func()

	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()

	for i := 0; i < 3; i++ {
		pipelineTransport, cleanupBackend, err = backend.PreparePipeline(ctx, psrpPipeline, payload)
		if err != nil {
			if errors.Is(err, transport.ErrUnauthorized) {
				continue
			}
			return nil, nil, nil, fmt.Errorf("prepare pipeline: %w", err)
		}

		// Invoke pipeline
		if err = psrpPipeline.Invoke(ctx); err != nil {
			cleanupBackend()
			if errors.Is(err, transport.ErrUnauthorized) {
				continue
			}
			return nil, nil, nil, fmt.Errorf("invoke pipeline: %w", err)
		}
		return psrpPipeline, pipelineTransport, cleanupBackend, nil
	}
	return nil, nil, nil, fmt.Errorf("failed to start pipeline after retries due to transport error")
}

// ExecuteAsync starts a PowerShell script execution but returns immediately without waiting
// for output. Returns the CommandID (PipelineID) for later recovery of output.
// This is useful for starting long-running commands and then disconnecting.
func (c *Client) ExecuteAsync(ctx context.Context, script string) (string, error) {
	c.mu.Lock()
	transportType := c.config.Transport
	c.mu.Unlock()

	if transportType == TransportHvSocket {
		return c.executeAsyncHvSocket(ctx, script)
	}

	// Standard (WSMan) Async Execution
	// We start the pipeline but do NOT start receiving loop, allowing output to buffer on server
	// or simply be ignored until later recovery/reconnection.
	psrpPipeline, _, _, err := c.startPipeline(ctx, script)
	if err != nil {
		return "", err
	}

	return strings.ToUpper(psrpPipeline.ID().String()), nil
}

// executeAsyncHvSocket handles detached execution for HvSocket.
func (c *Client) executeAsyncHvSocket(ctx context.Context, script string) (string, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return "", errors.New("client is closed")
	}
	psrpPool := c.psrpPool
	c.mu.Unlock()

	fileID := uuid.New().String()
	// We use $env:TEMP which resolves to the user's temp dir on the server.
	hvSocketFile := fmt.Sprintf(`$env:TEMP\psrp_out_%s.xml`, fileID)

	// Security: Encode the user script separately to prevent injection
	// The user script is executed via -EncodedCommand to avoid quote escaping issues
	encodedUserScript := encodePowerShellScript(script)

	// Create inner script that runs user command via encoded command,
	// exports output, and creates a completion marker.
	// This prevents script injection by not directly embedding user input.
	innerScript := fmt.Sprintf(
		`$p="%s"; try { & powershell.exe -NoProfile -NonInteractive `+
			`-EncodedCommand %s 2>&1 | Export-Clixml -Path $p -Depth 2 } `+
			`finally { New-Item "${p}_done" -ItemType File -Force }`,
		hvSocketFile, encodedUserScript)

	// Encode inner script for -EncodedCommand
	encodedInner := encodePowerShellScript(innerScript)

	// Run via WMI (Win32_Process)
	scriptToRun := fmt.Sprintf(
		`Invoke-CimMethod -ClassName Win32_Process -MethodName Create `+
			`-Arguments @{ CommandLine = "powershell.exe -NoProfile `+
			`-NonInteractive -EncodedCommand %s" } | Out-Null`,
		encodedInner)

	psrpPipeline, err := psrpPool.CreatePipeline(scriptToRun)
	if err != nil {
		return "", fmt.Errorf("create pipeline: %w", err)
	}

	c.mu.Lock()
	if c.outputFiles == nil {
		c.outputFiles = make(map[string]string)
	}
	c.outputFiles[psrpPipeline.ID().String()] = hvSocketFile
	c.mu.Unlock()

	// Invoke the pipeline (Ensure it uses startPipeline logic or manual?)
	// Manual here because WMI logic is special?
	// Actually, `startPipeline` does everything we need (Create+Prepare+Invoke).
	// But `scriptToRun` is different. can we use `startPipeline`?
	// `startPipeline` calls `backend.PreparePipeline`. For HvSocket it's a no-op returning nil.
	// So YES, we can use `startPipeline`!
	// Wait, `startPipeline` creates the pipeline from `script` argument.
	// We are creating pipeline from `scriptToRun`.
	// So we can wrap `startPipeline`?
	// But `startPipeline` assumes `script` is the one to create in CreatePipeline.
	// So:

	// We can't easily reuse `startPipeline` here because we need to register `outputFiles` *before* Invoke?
	// Actually we registered `outputFiles` before Invoke in original code.
	// If we use `startPipeline`, Invoke happens inside.
	// Is it safe to register `outputFiles` after Invoke?
	// As long as we do it before we return or disconnect, yes.
	// But `ExecuteAsync` for HvSocket waits for WMI launcher.

	// Let's keep manual logic for HvSocket to avoid regressions, just extract it.

	// #nosec G115 -- callID is always positive, starts at 0
	msgID := uint64(c.callID.Next())
	createPipelineData, err := psrpPipeline.GetCreatePipelineDataWithID(msgID)
	if err != nil {
		return "", fmt.Errorf("get create pipeline data: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(createPipelineData)

	// Prepare & Invoke
	// For HvSocket, Prepare is minimal, Invoke sends the message.
	c.cmdMu.Lock()
	_, _, err = c.backend.PreparePipeline(ctx, psrpPipeline, payload)
	c.cmdMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("prepare detached pipeline: %w", err)
	}

	if err := psrpPipeline.Invoke(ctx); err != nil {
		return "", fmt.Errorf("invoke detached launcher: %w", err)
	}

	// Wait synchronously for the WMI launcher to finish
	var errOutput []string
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg.Add(6)
	// Drain loops
	drain := func(ch <-chan *messages.Message) {
		defer wg.Done()
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
	go drain(psrpPipeline.Output())
	go drain(psrpPipeline.Warning())
	go drain(psrpPipeline.Verbose())
	go drain(psrpPipeline.Debug())
	go drain(psrpPipeline.Progress())
	go drain(psrpPipeline.Information())

	// Capture errors
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case err, ok := <-psrpPipeline.Error():
				if !ok {
					return
				}
				errOutput = append(errOutput, fmt.Sprintf("%v", err))
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()

	if err := psrpPipeline.Wait(); err != nil || len(errOutput) > 0 {
		return "", fmt.Errorf("failed to launch detached process: %v (errors: %v)", err, errOutput)
	}
	return psrpPipeline.ID().String(), nil
}

// runPipelineReceive runs a per-pipeline receive loop.
// It reads PSRP fragments from the pipeline-specific transport and feeds them to the pipeline.
// This is used by WSMan where each command has its own stdout stream.
func (c *Client) runPipelineReceive(ctx context.Context, transport io.Reader, pl *pipeline.Pipeline) {
	// Read PSRP fragments from the transport and feed them to the pipeline
	// Fragment format: ObjectId (8 bytes) + FragmentId (8 bytes) + Flags (1 byte) + BlobLength (4 bytes) + Blob
	for {
		// Check if context cancelled or pipeline done
		select {
		case <-ctx.Done():
			return
		case <-pl.Done():
			return
		default:
		}

		// Read fragment header (21 bytes: ObjectId=8, FragmentId=8, Flags=1, BlobLength=4)
		header := make([]byte, 21)
		if _, err := io.ReadFull(transport, header); err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return
			}
			// Transport error - fail the pipeline
			pl.Fail(fmt.Errorf("read fragment header: %w", err))
			return
		}

		// Parse blob length from last 4 bytes (big-endian)
		blobLen := int(header[17])<<24 | int(header[18])<<16 | int(header[19])<<8 | int(header[20])

		// Read blob data
		var blob []byte
		if blobLen > 0 {
			blob = make([]byte, blobLen)
			if _, err := io.ReadFull(transport, blob); err != nil {
				pl.Fail(fmt.Errorf("read fragment blob: %w", err))
				return
			}
		}

		// Parse the PSRP message from the fragment
		// Fragment flags: bit 0 = start, bit 1 = end
		flags := header[16]
		isStart := flags&1 != 0
		isEnd := flags&2 != 0

		if isStart {
			c.fragmentBuffer.Reset()
		}
		c.fragmentBuffer.Write(blob)

		if isEnd {
			// Full message collected

			// Parse and dispatch
			msg, err := messages.Decode(c.fragmentBuffer.Bytes())
			if err != nil {
				pl.Fail(fmt.Errorf("decode message: %w", err))
				return
			}

			if err := pl.HandleMessage(msg); err != nil {
				pl.Fail(fmt.Errorf("handle message: %w", err))
				return
			}
			// Reset buffer to free memory (optional, but good practice)
			c.fragmentBuffer.Reset()
		}
	}
}

// ShellID returns the identifier of the underlying shell.
// Returns empty string if not connected.
func (c *Client) ShellID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.backend == nil {
		return ""
	}
	return c.backend.ShellID()
}

// Disconnect disconnects from the remote session without closing it.
// The session remains running on the server and can be reconnected to later.
// Note: This only works if the backend supports it (WSMan) or via dirty PSRP disconnect (HvSocket).
func (c *Client) Disconnect(ctx context.Context) error {
	c.logInfo("Disconnect called")
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if backend supports Disconnect (WSMan)
	if wsmanBackend, ok := c.backend.(*powershell.WSManBackend); ok {
		if err := wsmanBackend.Disconnect(ctx); err != nil {
			return err
		}
		c.connected = false
		return nil
	}

	// For other transports (HvSocket), use PSRP-level disconnect (close transport without Close message)
	if c.psrpPool != nil {
		if err := c.psrpPool.Disconnect(); err != nil {
			return err
		}
		c.connected = false
		// c.backend = nil // Keep backend if needed? No, backend is dead.
		return nil
	}

	return fmt.Errorf("disconnect not supported on this transport or not connected")
}

// Reconnect connects to an existing disconnected shell.
// usage: client.Reconnect(ctx, shellID)
func (c *Client) Reconnect(ctx context.Context, shellID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Ensure backend is initialized (but not opened)
	if c.backend == nil {
		switch c.config.Transport {
		case TransportHvSocket:
			return fmt.Errorf("reconnect not supported on HvSocket transport")
		default: // WSMan
			if c.wsman == nil {
				return fmt.Errorf("wsman client not initialized")
			}
			wsmanBackend := powershell.NewWSManBackend(c.wsman, powershell.NewWSManTransport(nil, nil, ""))
			wsmanBackend.SetResourceURI(c.buildResourceURI())
			c.backend = wsmanBackend
		}
	}

	// 2. Call Reattach on the backend
	// 2. Call Reattach on the backend
	// We MUST create a new RunspacePool instance because Pool objects are single-use (cannot be re-opened).
	// Even for reconnection, we start a fresh PSRP state machine.

	// Get transport from backend
	transport := c.backend.Transport()
	if t, ok := transport.(*powershell.WSManTransport); ok {
		t.SetContext(ctx)
	}

	// Create new pool
	c.psrpPool = runspace.New(transport, c.poolID)

	// Configure logging
	if c.slogLogger != nil {
		_ = c.psrpPool.SetSlogLogger(c.slogLogger) //nolint:errcheck // Best-effort logging config
	} else if os.Getenv("PSRP_DEBUG") != "" || os.Getenv("PSRP_LOG_LEVEL") != "" {
		c.psrpPool.EnableDebugLogging()
	}

	// Configure pool size
	maxRunspaces := c.config.MaxRunspaces
	if maxRunspaces <= 0 {
		maxRunspaces = 1
	}
	_ = c.psrpPool.SetMinRunspaces(1)            //nolint:errcheck // Called before Open()
	_ = c.psrpPool.SetMaxRunspaces(maxRunspaces) //nolint:errcheck // Called before Open()

	if err := c.backend.Reattach(ctx, c.psrpPool, shellID); err != nil {
		return fmt.Errorf("backend reattach: %w", err)
	}
	c.connected = true

	// Sync message ID (SessionCapability=1, ConnectRunspacePool=2 were sent)
	c.callID.Set(2)
	c.psrpPool.SetMessageID(2)

	// Initialize semaphore for concurrent command limiting (same as Connect)
	if c.semaphore == nil {
		maxRunspaces := c.config.MaxRunspaces
		if maxRunspaces == 0 && c.config.MaxConcurrentCommands > 0 {
			maxRunspaces = c.config.MaxConcurrentCommands
		}
		if maxRunspaces <= 0 {
			maxRunspaces = 1 // Default safe
		}
		c.semaphore = newPoolSemaphore(maxRunspaces, c.config.MaxQueueSize, c.config.Timeout)
	}

	return nil
}

// SetSessionID sets the WSMan SessionID (useful for testing session persistence).
func (c *Client) SetSessionID(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wsman != nil {
		c.wsman.SetSessionID(sessionID)
	}
}

// PoolID returns the PSRP RunspacePool ID.
func (c *Client) PoolID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.poolID.String()
}

// SetPoolID sets the PSRP RunspacePool ID (must be called before Connect/Reconnect).
func (c *Client) SetPoolID(poolID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, err := uuid.Parse(poolID)
	if err != nil {
		return err
	}
	c.poolID = id
	return nil
}

// DisconnectedPipeline represents a pipeline within a disconnected session.
type DisconnectedPipeline struct {
	CommandID string
}

// DisconnectedSession represents a disconnected PowerShell session that can be reconnected.
type DisconnectedSession struct {
	ShellID   string
	Name      string
	State     string
	Owner     string
	Pipelines []DisconnectedPipeline
}

// ListDisconnectedSessions queries the server for disconnected shells and their pipelines.
func (c *Client) ListDisconnectedSessions(ctx context.Context) ([]DisconnectedSession, error) {
	c.mu.Lock()
	wClient := c.wsman
	c.mu.Unlock()

	if wClient == nil {
		return nil, fmt.Errorf("list sessions not supported on this transport")
	}

	// Get shells
	shells, err := wClient.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate shells: %w", err)
	}

	// Filter out current shell from list
	var currentShellID string
	if c.backend != nil {
		currentShellID = c.backend.ShellID()
	}

	// Build sessions with their pipelines
	var sessions []DisconnectedSession
	for _, shell := range shells {
		// Skip our own session
		if currentShellID != "" && strings.EqualFold(shell.ShellID, currentShellID) {
			continue
		}

		session := DisconnectedSession{
			ShellID: shell.ShellID,
			Name:    shell.Name,
			State:   shell.State,
			Owner:   shell.Owner,
		}

		// Get pipelines for this shell
		commandIDs, err := wClient.EnumerateCommands(ctx, shell.ShellID)
		if err == nil && len(commandIDs) > 0 {
			for _, cmdID := range commandIDs {
				session.Pipelines = append(session.Pipelines, DisconnectedPipeline{CommandID: cmdID})
			}
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// RemoveDisconnectedSession deletes a disconnected session on the server.
func (c *Client) RemoveDisconnectedSession(ctx context.Context, session DisconnectedSession) error {
	c.mu.Lock()
	wClient := c.wsman
	c.mu.Unlock()

	if wClient == nil {
		return fmt.Errorf("remove session not supported on this transport")
	}

	// Construct EndpointReference for the session
	epr := &wsman.EndpointReference{
		ResourceURI: wsman.ResourceURIPowerShell, // Default to PowerShell URI
		Selectors: []wsman.Selector{
			{Name: "ShellId", Value: session.ShellID},
		},
	}

	// Try to Signal Terminate first (to force close connected sessions)
	// We ignore errors here because the session might already be broken or not support signal
	_ = wClient.Signal(ctx, epr, "", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate")

	if err := wClient.Delete(ctx, epr); err != nil {
		// If the shell is not found, it means it's already gone/closed (possibly by the Signal above).
		// We treat this as success.
		// Error code 2150858843 = "The request for the Windows Remote Shell with ShellId ... failed because the shell was not found"
		if strings.Contains(err.Error(), "2150858843") || strings.Contains(err.Error(), "shell was not found") {
			return nil
		}
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// RecoverPipelineOutput retrieves buffered output from a disconnected pipeline.
// This reconnects to the shell and receives any output that was buffered before disconnect.
func (c *Client) RecoverPipelineOutput(ctx context.Context, shellID, commandID string) (*Result, error) {
	// Normalize IDs to Uppercase for WinRM
	shellID = strings.ToUpper(shellID)
	commandID = strings.ToUpper(commandID)

	// 1. Reconnect if sending new command/connecting to shell
	// Note: If we just called ReconnectSession (which sets c.connected=true for HvSocket),
	// we should SKIP c.Reconnect() because c.Reconnect() logic is WSMan specific or might be redundant.
	c.mu.Lock()
	alreadyConnected := c.connected && c.psrpPool != nil
	c.mu.Unlock()

	if !alreadyConnected {
		if err := c.Reconnect(ctx, shellID); err != nil {
			return nil, fmt.Errorf("reconnect: %w", err)
		}
	} else {
		// Verify pool is open logic is handled by AdoptPipeline check later
	}

	// 2. File-Based Recovery (HvSocket)
	c.mu.Lock()
	recoveryFile, hasRecoveryFile := c.outputFiles[commandID]
	c.mu.Unlock()

	if hasRecoveryFile {
		// We use the new session to Import the CLIXML file and emit it.
		// We poll for the '_done' marker file to ensure specific independent process has finished.
		// Loop checks every 500ms. Context cancellation handles timeout.
		script := fmt.Sprintf(`
			$f="%s"
			$d="${f}_done"
			while (-not (Test-Path $d)) { Start-Sleep -Milliseconds 500 }
			if (Test-Path $f) {
				Import-Clixml -Path $f
				Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
			}
			Remove-Item $d -Force -ErrorAction SilentlyContinue
		`, recoveryFile)
		return c.Execute(ctx, script)
	}

	c.mu.Lock()
	backend := c.backend
	psrpPool := c.psrpPool
	wsmanClient := c.wsman
	c.mu.Unlock()

	if backend == nil || psrpPool == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Helper to collect results (reused from Execute logic)
	collectResults := func(pl *pipeline.Pipeline) (*Result, error) {
		var (
			output     []interface{}
			errOutput  []interface{}
			infoOutput []interface{}
			hadErrors  bool
			wg         sync.WaitGroup
			mu         sync.Mutex
		)

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

		// We only collect output and errors for recovery for now (to match WSMan simple recovery),
		// but we drain others to prevent blocking
		drainVoid := func(ch <-chan *messages.Message) {
			defer wg.Done()
			for range ch {
			}
		}

		wg.Add(7)
		go drainChannel(pl.Output(), &output, false)
		go drainChannel(pl.Error(), &errOutput, true)
		go drainVoid(pl.Warning())
		go drainVoid(pl.Verbose())
		go drainVoid(pl.Debug())
		go drainVoid(pl.Progress())
		go drainChannel(pl.Information(), &infoOutput, false)

		wg.Wait()

		if err := pl.Wait(); err != nil {
			hadErrors = true
			if len(errOutput) == 0 {
				errOutput = append(errOutput, err.Error())
			}
		}

		return &Result{
			Output:      output,
			Errors:      errOutput,
			Information: infoOutput,
			HadErrors:   hadErrors,
		}, nil
	}

	// 1. WSMan Specific Path
	if wsmanBackend, ok := backend.(*powershell.WSManBackend); ok && wsmanClient != nil {
		// Use standard PSRP pipeline logic but manually drive the transport receive loop
		// because WSMan requires per-command receive requests.

		cmdUUID, err := uuid.Parse(commandID)
		if err != nil {
			return nil, fmt.Errorf("invalid command id: %w", err)
		}

		// Create new pipeline
		pl := pipeline.NewWithID(psrpPool, c.poolID, cmdUUID)

		// Register with pool (so handleMessage works)
		if err := psrpPool.AdoptPipeline(pl); err != nil {
			return nil, fmt.Errorf("adopt pipeline: %w", err)
		}

		// Create Transport specifically for this recovered command
		// Using the normalized IDs we ensured earlier
		epr := wsmanBackend.EPR()
		transport := powershell.NewWSManTransport(wsmanClient, epr, commandID)
		transport.SetContext(ctx)

		// Start the receive loop in background
		// This reads fragments from WSMan, defragments them, and pushes Messages to the pipeline
		go func() {
			c.runPipelineReceive(ctx, transport, pl)
			// Ensure pipeline is closed when transport is done
			// pipeline doesn't have Close(), it checks for Done channel or Context

		}()

		// Wait for results
		return collectResults(pl)
	}

	// 2. Generic PSRP Path (HvSocket / OutOfProc)
	// Create a pipeline object with the specific ID
	cmdUUID, err := uuid.Parse(commandID)
	if err != nil {
		return nil, fmt.Errorf("invalid command id: %w", err)
	}

	// Create new pipeline attached to pool with specific ID
	pl := pipeline.NewWithID(psrpPool, c.poolID, cmdUUID)

	// Register with pool
	if err := psrpPool.AdoptPipeline(pl); err != nil {
		return nil, fmt.Errorf("adopt pipeline: %w", err)
	}

	// Ensure dispatch loop is running (safe to call multiple times)
	// For HvSocket reconnection, Reattach calls pool.Connect which starts it.
	// But just in case:
	psrpPool.StartDispatchLoop()

	// Wait/Drain
	return collectResults(pl)
}
