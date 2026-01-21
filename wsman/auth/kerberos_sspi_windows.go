//go:build windows
// +build windows

package auth

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/sspi"
)

// SSPIConfig holds configuration for the SSPI provider.
type SSPIConfig struct {
	UseDefaultCreds bool
	Username        string
	Password        string
	Domain          string
}

// SSPIProvider implements the SecurityProvider interface using Windows SSPI.
// It uses the Negotiate security package (SPNEGO) with Channel Binding Token support.
type SSPIProvider struct {
	username        string
	password        string
	domain          string
	targetSPN       string
	complete        bool
	channelBindings []byte // Store CBT for reuse in Update calls

	// Internal state
	cred       *sspi.Credentials
	ctx        *sspi.Context
	targetName *uint16
	maxToken   uint32
}

// NewSSPIProvider creates a new SSPI-based provider.
func NewSSPIProvider(config SSPIConfig, targetSPN string) (*SSPIProvider, error) {
	// Query package info for max token size
	pkgInfo, err := sspi.QueryPackageInfo(sspi.NEGOSSP_NAME)
	if err != nil {
		return nil, fmt.Errorf("query negotiate package: %w", err)
	}

	return &SSPIProvider{
		username:  config.Username,
		password:  config.Password,
		domain:    config.Domain,
		targetSPN: targetSPN,
		maxToken:  pkgInfo.MaxToken,
	}, nil
}

// Complete returns true if the authentication exchange is complete.
func (p *SSPIProvider) Complete() bool {
	return p.complete
}

// Wrap is a no-op for HTTP auth.
func (p *SSPIProvider) Wrap(data []byte) ([]byte, error) {
	return data, nil
}

// Unwrap is a no-op for HTTP auth.
func (p *SSPIProvider) Unwrap(data []byte) ([]byte, error) {
	return data, nil
}

// Step performs a step in the SSPI handshake.
func (p *SSPIProvider) Step(ctx context.Context, serverToken []byte) ([]byte, bool, error) {
	if p.complete {
		return nil, true, nil
	}

	fmt.Printf("DEBUG: Step called. serverToken len=%d\n", len(serverToken))

	// First call: Acquire credentials and create context
	if p.cred == nil {
		var err error

		// Acquire credentials using NEGOSSP_NAME for SPNEGO
		if p.username == "" {
			// Use current user (SSO)
			fmt.Printf("DEBUG: Acquiring current user credentials (SSO)\n")
			p.cred, err = sspi.AcquireCredentials("", sspi.NEGOSSP_NAME, sspi.SECPKG_CRED_OUTBOUND, nil)
		} else {
			// Build auth identity for explicit credentials
			fmt.Printf("DEBUG: Acquiring user credentials for %s\\%s\n", p.domain, p.username)
			identity, err2 := buildAuthIdentity(p.domain, p.username, p.password)
			if err2 != nil {
				return nil, false, fmt.Errorf("build auth identity: %w", err2)
			}
			p.cred, err = sspi.AcquireCredentials("", sspi.NEGOSSP_NAME, sspi.SECPKG_CRED_OUTBOUND, identity)
		}
		if err != nil {
			return nil, false, fmt.Errorf("SSPI acquire credentials: %w", err)
		}

		// Create client context with standard flags
		flags := sspi.ISC_REQ_CONNECTION |
			sspi.ISC_REQ_MUTUAL_AUTH |
			sspi.ISC_REQ_DELEGATE |
			sspi.ISC_REQ_INTEGRITY |
			sspi.ISC_REQ_CONFIDENTIALITY |
			sspi.ISC_REQ_REPLAY_DETECT |
			sspi.ISC_REQ_SEQUENCE_DETECT

		p.ctx = sspi.NewClientContext(p.cred, uint32(flags))

		// Convert target name to UTF-16
		tname, err := syscall.UTF16PtrFromString(p.targetSPN)
		if err != nil {
			return nil, false, fmt.Errorf("convert SPN: %w", err)
		}
		p.targetName = tname

		// Store CBT from context for reuse
		if cbtHash, ok := ctx.Value(ContextKeyChannelBindings).([]byte); ok && len(cbtHash) > 0 {
			p.channelBindings = makeChannelBindings(cbtHash)
			fmt.Printf("DEBUG: SSPI Negotiate with CBT. HashLen=%d, StructLen=%d\n", len(cbtHash), len(p.channelBindings))
		} else {
			fmt.Printf("DEBUG: SSPI Negotiate without CBT\n")
		}

		fmt.Printf("DEBUG: SSPI TargetSPN: %s\n", p.targetSPN)
	}

	// Call UpdateContextWithChannelBindings
	outputToken, authCompleted, err := p.updateContextWithChannelBindings(serverToken)
	if err != nil {
		return nil, false, err
	}

	p.complete = authCompleted
	return outputToken, authCompleted, nil
}

// updateContextWithChannelBindings performs SSPI context update with optional channel bindings.
func (p *SSPIProvider) updateContextWithChannelBindings(serverToken []byte) ([]byte, bool, error) {
	// Prepare input buffers - TOKEN first, then CHANNEL_BINDINGS
	var inBuf [2]sspi.SecBuffer

	// TOKEN buffer (always present, even if empty)
	inBuf[0].Set(sspi.SECBUFFER_TOKEN, serverToken)
	inBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &inBuf[0],
	}

	// Add channel bindings if available
	if len(p.channelBindings) > 0 {
		inBuf[1].Set(sspi.SECBUFFER_CHANNEL_BINDINGS, p.channelBindings)
		inBufs.BuffersCount = 2
	}

	// Prepare output buffer
	dst := make([]byte, p.maxToken)
	var outBuf [1]sspi.SecBuffer
	outBuf[0].Set(sspi.SECBUFFER_TOKEN, dst)
	outBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &outBuf[0],
	}

	// Call Update
	ret := p.ctx.Update(p.targetName, outBufs, inBufs)
	n := int(outBuf[0].BufferSize)

	fmt.Printf("DEBUG: SSPI result=0x%x, tokenLen=%d\n", uint32(ret), n)
	if n > 4 {
		fmt.Printf("DEBUG: Token prefix: %x\n", dst[:4])
	}

	switch ret {
	case sspi.SEC_E_OK:
		return dst[:n], true, nil
	case sspi.SEC_I_CONTINUE_NEEDED:
		return dst[:n], false, nil
	case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
		completeRet := sspi.CompleteAuthToken(p.ctx.Handle, outBufs)
		if completeRet != sspi.SEC_E_OK {
			return nil, false, fmt.Errorf("SSPI complete auth: 0x%x", completeRet)
		}
		if ret == sspi.SEC_I_COMPLETE_AND_CONTINUE {
			return dst[:n], false, nil
		}
		return dst[:n], true, nil
	default:
		return nil, false, fmt.Errorf("SSPI error: 0x%x", uint32(ret))
	}
}

// Close releases the SSPI resources.
func (p *SSPIProvider) Close() error {
	var errs []string

	if p.ctx != nil {
		if err := p.ctx.Release(); err != nil {
			errs = append(errs, fmt.Sprintf("ctx release: %v", err))
		}
		p.ctx = nil
	}
	if p.cred != nil {
		if err := p.cred.Release(); err != nil {
			errs = append(errs, fmt.Sprintf("cred release: %v", err))
		}
		p.cred = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("SSPI close errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// buildAuthIdentity creates a SEC_WINNT_AUTH_IDENTITY structure.
func buildAuthIdentity(domain, username, password string) (*byte, error) {
	d, err := syscall.UTF16FromString(domain)
	if err != nil {
		return nil, err
	}
	u, err := syscall.UTF16FromString(username)
	if err != nil {
		return nil, err
	}
	pw, err := syscall.UTF16FromString(password)
	if err != nil {
		return nil, err
	}
	identity := &sspi.SEC_WINNT_AUTH_IDENTITY{
		User:           &u[0],
		UserLength:     uint32(len(u) - 1),
		Domain:         &d[0],
		DomainLength:   uint32(len(d) - 1),
		Password:       &pw[0],
		PasswordLength: uint32(len(pw) - 1),
		Flags:          sspi.SEC_WINNT_AUTH_IDENTITY_UNICODE,
	}
	return (*byte)(unsafe.Pointer(identity)), nil
}
