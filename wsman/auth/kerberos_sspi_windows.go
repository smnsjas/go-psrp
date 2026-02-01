//go:build windows
// +build windows

package auth

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/sspi"
)

const secEInvalidToken = 0x80090308

// SSPIConfig holds configuration for the SSPI provider.
type SSPIConfig struct {
	UseDefaultCreds bool
	Username        string
	Password        string
	Domain          string
	PackageName     string
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
	isHTTPS         bool

	// Internal state
	cred       *sspi.Credentials
	ctx        *sspi.Context
	targetName *uint16
	maxToken   uint32
	packageName string
}

// NewSSPIProvider creates a new SSPI-based provider.
func NewSSPIProvider(config SSPIConfig, targetSPN string) (*SSPIProvider, error) {
	packageName := config.PackageName
	if packageName == "" {
		packageName = sspi.NEGOSSP_NAME
	}

	// Query package info for max token size
	pkgInfo, err := sspi.QueryPackageInfo(packageName)
	if err != nil {
		return nil, fmt.Errorf("query SSPI package: %w", err)
	}

	return &SSPIProvider{
		username:  config.Username,
		password:  config.Password,
		domain:    config.Domain,
		targetSPN: targetSPN,
		maxToken:  pkgInfo.MaxToken,
		packageName: packageName,
	}, nil
}

// Complete returns true if the authentication exchange is complete.
func (p *SSPIProvider) Complete() bool {
	return p.complete
}

// Wrap encrypts data for HTTP transport using SSPI sealing.
// This is ONLY called for HTTP (not HTTPS/TLS) - encryption is application-layer.
func (p *SSPIProvider) Wrap(data []byte) ([]byte, error) {
	if p.isHTTPS {
		return nil, fmt.Errorf("wrap called for HTTPS connection (encryption handled by TLS)")
	}
	if p.ctx == nil || !p.complete {
		return nil, fmt.Errorf("cannot wrap: SSPI context not initialized")
	}

	_, _, blockSize, securityTrailer, err := p.ctx.Sizes()
	if err != nil {
		return nil, fmt.Errorf("query SSPI sizes: %w", err)
	}

	var buffers [3]sspi.SecBuffer
	buffers[0].Set(sspi.SECBUFFER_TOKEN, make([]byte, securityTrailer))
	buffers[1].Set(sspi.SECBUFFER_DATA, data)
	buffers[2].Set(sspi.SECBUFFER_PADDING, make([]byte, blockSize))

	ret := sspi.EncryptMessage(p.ctx.Handle, 0, sspi.NewSecBufferDesc(buffers[:]), 0)
	if ret != sspi.SEC_E_OK {
		return nil, sspiStatusError{code: uint32(ret)}
	}

	signature := buffers[0].Bytes()
	encryptedData := append(buffers[1].Bytes(), buffers[2].Bytes()...)
	totalLen := 4 + len(signature) + len(encryptedData)
	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(out[:4], uint32(len(signature)))
	copy(out[4:], signature)
	copy(out[4+len(signature):], encryptedData)

	return out, nil
}

// Unwrap decrypts data from HTTP transport.
// This is ONLY called for HTTP (not HTTPS/TLS) - decryption is application-layer.
func (p *SSPIProvider) Unwrap(data []byte) ([]byte, error) {
	if p.isHTTPS {
		return nil, fmt.Errorf("unwrap called for HTTPS connection (encryption handled by TLS)")
	}
	if p.ctx == nil || !p.complete {
		return nil, fmt.Errorf("cannot unwrap: SSPI context not initialized")
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for MS-WSMV format: %d bytes", len(data))
	}

	signatureLen := binary.LittleEndian.Uint32(data[:4])
	const maxSignatureLen = 100 * 1024 * 1024
	if signatureLen > maxSignatureLen {
		return nil, fmt.Errorf("signature length too large: %d > %d", signatureLen, maxSignatureLen)
	}
	if int64(signatureLen) > int64(len(data)-4) {
		return nil, fmt.Errorf("data too short for signature: need %d, have %d", 4+int(signatureLen), len(data))
	}

	stream := data[4:]
	var buffers [2]sspi.SecBuffer
	buffers[0].Set(sspi.SECBUFFER_STREAM, stream)
	buffers[1].Set(sspi.SECBUFFER_DATA, []byte{})

	var qop uint32
	ret := sspi.DecryptMessage(p.ctx.Handle, sspi.NewSecBufferDesc(buffers[:]), 0, &qop)
	if ret != sspi.SEC_E_OK {
		return nil, sspiStatusError{code: uint32(ret)}
	}

	return buffers[1].Bytes(), nil
}

// ProcessResponse is a no-op for SSPI as Step handles the token processing.
func (p *SSPIProvider) ProcessResponse(ctx context.Context, authHeader string) error {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil
	}
	token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil || len(token) == 0 {
		return nil
	}

	outputToken, authCompleted, err := p.Step(ctx, token)
	if err != nil {
		return err
	}
	if len(outputToken) > 0 && !authCompleted {
		slog.Debug("SSPI ProcessResponse returned extra token", "tokenLen", len(outputToken))
	}
	return nil
}

// Step performs a step in the SSPI handshake.
func (p *SSPIProvider) Step(ctx context.Context, serverToken []byte) ([]byte, bool, error) {
	if p.complete {
		return nil, true, nil
	}

	slog.Debug("SSPI Step called", "serverTokenLen", len(serverToken))

	// First call: Acquire credentials and create context
	if p.cred == nil {
		if err := p.initializeCredentials(); err != nil {
			return nil, false, err
		}

		// Convert target name to UTF-16
		tname, err := syscall.UTF16PtrFromString(p.targetSPN)
		if err != nil {
			return nil, false, fmt.Errorf("convert SPN to UTF-16: %w", err)
		}
		p.targetName = tname

		isHTTPS, _ := ctx.Value(ContextKeyIsHTTPS).(bool)
		p.isHTTPS = isHTTPS

		// Store CBT from context for reuse
		if cbtHash, ok := ctx.Value(ContextKeyChannelBindings).([]byte); ok && len(cbtHash) > 0 {
			p.channelBindings = makeChannelBindings(cbtHash)
			slog.Debug("SSPI Negotiate with CBT", "hashLen", len(cbtHash), "structLen", len(p.channelBindings))
		} else {
			slog.Debug("SSPI Negotiate without CBT")
		}

		slog.Debug("SSPI configuration", "targetSPN", p.targetSPN)
	}

	// Call UpdateContextWithChannelBindings
	outputToken, authCompleted, err := p.updateContextWithChannelBindings(serverToken)
	if err != nil {
		var sspiErr sspiStatusError
		if errors.As(err, &sspiErr) && sspiErr.code == secEInvalidToken && len(serverToken) == 0 {
			slog.Debug("SSPI invalid token on initial step, resetting context", "code", fmt.Sprintf("0x%x", sspiErr.code))
			if p.ctx != nil {
				_ = p.ctx.Release()
				p.ctx = nil
			}
			p.complete = false
			if initErr := p.initializeCredentials(); initErr != nil {
				return nil, false, initErr
			}
			outputToken, authCompleted, err = p.updateContextWithChannelBindings(serverToken)
			if err != nil {
				return nil, false, err
			}
		} else {
			return nil, false, err
		}
	}

	p.complete = authCompleted
	return outputToken, authCompleted, nil
}

// initializeCredentials acquires SSPI credentials and creates the client context.
func (p *SSPIProvider) initializeCredentials() error {
	var err error

	// Acquire credentials using NEGOSSP_NAME for SPNEGO
	if p.username == "" {
		// Use current user (SSO)
		slog.Debug("Acquiring current user credentials (SSO)")
		p.cred, err = sspi.AcquireCredentials("", p.packageName, sspi.SECPKG_CRED_OUTBOUND, nil)
	} else {
		// Build auth identity for explicit credentials
		slog.Debug("Acquiring user credentials", "domain", p.domain, "username", p.username)
		identity, identityErr := buildAuthIdentity(p.domain, p.username, p.password)
		if identityErr != nil {
			return fmt.Errorf("build auth identity: %w", identityErr)
		}
		p.cred, err = sspi.AcquireCredentials("", p.packageName, sspi.SECPKG_CRED_OUTBOUND, identity)
	}
	if err != nil {
		return fmt.Errorf("acquire SSPI credentials: %w", err)
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
	return nil
}

// updateContextWithChannelBindings performs SSPI context update with optional channel bindings.
type sspiStatusError struct {
	code uint32
}

func (e sspiStatusError) Error() string {
	return fmt.Sprintf("SSPI InitializeSecurityContext: error 0x%x", e.code)
}

func (p *SSPIProvider) updateContextWithChannelBindings(serverToken []byte) ([]byte, bool, error) {
	// Prepare input buffers.
	// On the first call, SSPI expects no input token. Passing an empty
	// TOKEN buffer can return SEC_E_INVALID_TOKEN on some systems.
	var inBuf [2]sspi.SecBuffer
	var inBufs *sspi.SecBufferDesc

	if len(serverToken) > 0 {
		// TOKEN buffer first
		inBuf[0].Set(sspi.SECBUFFER_TOKEN, serverToken)
		inBufs = &sspi.SecBufferDesc{
			Version:      sspi.SECBUFFER_VERSION,
			BuffersCount: 1,
			Buffers:      &inBuf[0],
		}

		// Add channel bindings if available
		if len(p.channelBindings) > 0 {
			inBuf[1].Set(sspi.SECBUFFER_CHANNEL_BINDINGS, p.channelBindings)
			inBufs.BuffersCount = 2
		}
	} else if len(p.channelBindings) > 0 {
		// First call with CBT only (no input token)
		inBuf[0].Set(sspi.SECBUFFER_CHANNEL_BINDINGS, p.channelBindings)
		inBufs = &sspi.SecBufferDesc{
			Version:      sspi.SECBUFFER_VERSION,
			BuffersCount: 1,
			Buffers:      &inBuf[0],
		}
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

	slog.Debug("SSPI Update result", "returnCode", fmt.Sprintf("0x%x", uint32(ret)), "tokenLen", n)

	switch ret {
	case sspi.SEC_E_OK:
		return dst[:n], true, nil
	case sspi.SEC_I_CONTINUE_NEEDED:
		return dst[:n], false, nil
	case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
		completeRet := sspi.CompleteAuthToken(p.ctx.Handle, outBufs)
		if completeRet != sspi.SEC_E_OK {
			return nil, false, fmt.Errorf("complete auth token: SSPI error 0x%x", uint32(completeRet))
		}
		if ret == sspi.SEC_I_COMPLETE_AND_CONTINUE {
			return dst[:n], false, nil
		}
		return dst[:n], true, nil
	default:
		return nil, false, sspiStatusError{code: uint32(ret)}
	}
}

// Close releases the SSPI resources.
func (p *SSPIProvider) Close() error {
	var errs []string

	if p.ctx != nil {
		if err := p.ctx.Release(); err != nil {
			errs = append(errs, fmt.Sprintf("context release: %v", err))
		}
		p.ctx = nil
	}
	if p.cred != nil {
		if err := p.cred.Release(); err != nil {
			errs = append(errs, fmt.Sprintf("credentials release: %v", err))
		}
		p.cred = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("SSPI close errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// buildAuthIdentity creates a SEC_WINNT_AUTH_IDENTITY structure for explicit credentials.
func buildAuthIdentity(domain, username, password string) (*byte, error) {
	d, err := syscall.UTF16FromString(domain)
	if err != nil {
		return nil, fmt.Errorf("encode domain to UTF-16: %w", err)
	}
	u, err := syscall.UTF16FromString(username)
	if err != nil {
		return nil, fmt.Errorf("encode username to UTF-16: %w", err)
	}
	pw, err := syscall.UTF16FromString(password)
	if err != nil {
		return nil, fmt.Errorf("encode password to UTF-16: %w", err)
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
