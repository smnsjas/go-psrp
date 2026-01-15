package winrs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smnsjas/go-psrp/wsman"
)

// shellConfig holds the configuration for a Shell.
type shellConfig struct {
	workingDir  string
	environment map[string]string
	idleTimeout time.Duration
	codepage    int
	noProfile   bool
}

// Option configures a Shell.
type Option func(*shellConfig)

// WithWorkingDirectory sets the shell's initial working directory.
func WithWorkingDirectory(dir string) Option {
	return func(c *shellConfig) { c.workingDir = dir }
}

// WithEnvironment sets environment variables for the shell.
func WithEnvironment(env map[string]string) Option {
	return func(c *shellConfig) { c.environment = env }
}

// WithIdleTimeout sets the shell idle timeout.
// If the shell is idle for this duration, the server may close it.
func WithIdleTimeout(d time.Duration) Option {
	return func(c *shellConfig) { c.idleTimeout = d }
}

// WithCodepage sets the console codepage.
// Common values: 437 (OEM/DOS), 65001 (UTF-8).
func WithCodepage(cp int) Option {
	return func(c *shellConfig) { c.codepage = cp }
}

// WithNoProfile prevents loading the user profile on shell creation.
func WithNoProfile() Option {
	return func(c *shellConfig) { c.noProfile = true }
}

// Shell represents a WinRS cmd.exe shell session.
type Shell struct {
	transport Transport
	epr       *wsman.EndpointReference
	config    shellConfig
	closed    bool
	mu        sync.Mutex
}

// NewShell creates a new WinRS shell on the remote system.
func NewShell(ctx context.Context, transport Transport, opts ...Option) (*Shell, error) {
	if transport == nil {
		return nil, fmt.Errorf("winrs: transport is nil")
	}

	cfg := shellConfig{
		idleTimeout: 30 * time.Minute,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	options := map[string]string{
		"ResourceURI": wsman.ResourceURIWinRS,
	}

	if cfg.noProfile {
		options["WINRS_NOPROFILE"] = "TRUE"
	}
	if cfg.codepage > 0 {
		options["WINRS_CODEPAGE"] = fmt.Sprintf("%d", cfg.codepage)
	}
	if cfg.idleTimeout > 0 {
		options["IdleTimeout"] = formatDuration(cfg.idleTimeout)
	}

	epr, err := transport.Create(ctx, options, "")
	if err != nil {
		return nil, fmt.Errorf("winrs: create shell: %w", err)
	}

	return &Shell{
		transport: transport,
		epr:       epr,
		config:    cfg,
	}, nil
}

// ID returns the shell ID.
func (s *Shell) ID() string {
	for _, sel := range s.epr.Selectors {
		if sel.Name == "ShellId" {
			return sel.Value
		}
	}
	return ""
}

// EPR returns the shell's endpoint reference for low-level operations.
func (s *Shell) EPR() *wsman.EndpointReference {
	return s.epr
}

// Close terminates the shell.
func (s *Shell) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if err := s.transport.Delete(ctx, s.epr); err != nil {
		return fmt.Errorf("winrs: close shell: %w", err)
	}
	return nil
}

// formatDuration converts a time.Duration to ISO 8601 duration string (PTnS).
func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	return fmt.Sprintf("PT%dS", seconds)
}
