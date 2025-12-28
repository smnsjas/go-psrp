//go:build windows

package auth

import (
	"context"
	"fmt"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
)

// SSPIProvider implements SecurityProvider using Windows native SSPI.
// This enables Single Sign-On (SSO) using the logged-in Windows user credentials.
type SSPIProvider struct {
	cred      *sspi.Credentials
	ctx       *negotiate.ClientContext
	targetSPN string
	complete  bool
}

// SSPIConfig holds the configuration for the SSPIProvider.
type SSPIConfig struct {
	// UseDefaultCreds uses the current logged-in user's credentials (SSO).
	UseDefaultCreds bool

	// If not using default creds, provide explicit credentials.
	Username string
	Password string
	Domain   string
}

// NewSSPIProvider creates a new Windows SSPI-based Kerberos/Negotiate provider.
func NewSSPIProvider(cfg SSPIConfig, targetSPN string) (*SSPIProvider, error) {
	var cred *sspi.Credentials
	var err error

	if cfg.UseDefaultCreds {
		// Use current user's credentials (SSO)
		cred, err = negotiate.AcquireCurrentUserCredentials()
	} else {
		// Use explicit credentials
		cred, err = negotiate.AcquireUserCredentials(cfg.Domain, cfg.Username, cfg.Password)
	}
	if err != nil {
		return nil, fmt.Errorf("acquire credentials: %w", err)
	}

	return &SSPIProvider{
		cred:      cred,
		targetSPN: targetSPN,
	}, nil
}

// Step performs a SPNEGO step using Windows SSPI.
func (p *SSPIProvider) Step(ctx context.Context, inputToken []byte) ([]byte, bool, error) {
	var outputToken []byte
	var err error

	if p.ctx == nil {
		// First step - initialize context
		p.ctx, outputToken, err = negotiate.NewClientContext(p.cred, p.targetSPN)
		if err != nil {
			return nil, false, fmt.Errorf("init security context: %w", err)
		}
	} else {
		// Subsequent steps - update context with server token
		p.complete, outputToken, err = p.ctx.Update(inputToken)
		if err != nil {
			return nil, false, fmt.Errorf("update security context: %w", err)
		}
	}

	// If outputToken is nil and we're complete, we're done
	if p.complete {
		return outputToken, false, nil
	}

	// Not complete - continue needed
	return outputToken, true, nil
}

// Complete returns true if the security context is established.
func (p *SSPIProvider) Complete() bool {
	return p.complete
}

// Close releases SSPI resources.
func (p *SSPIProvider) Close() error {
	if p.ctx != nil {
		if err := p.ctx.Release(); err != nil {
			return err
		}
	}
	if p.cred != nil {
		return p.cred.Release()
	}
	return nil
}
