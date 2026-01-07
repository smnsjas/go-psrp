package auth

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/Azure/go-ntlmssp"
	ntlmcbt "github.com/smnsjas/go-ntlm-cbt"
)

// NTLMAuth implements NTLM authentication with optional Channel Binding Token (CBT) support.
type NTLMAuth struct {
	creds     Credentials
	enableCBT bool
}

// NTLMAuthOption configures NTLM authentication.
type NTLMAuthOption func(*NTLMAuth)

// WithCBT enables Channel Binding Tokens for Extended Protection.
// When enabled, the NTLM authentication will include a CBT derived from
// the TLS server certificate, protecting against NTLM relay attacks.
func WithCBT(enable bool) NTLMAuthOption {
	return func(a *NTLMAuth) {
		a.enableCBT = enable
	}
}

// NewNTLMAuth creates a new NTLM authentication handler.
// By default, CBT is disabled for backwards compatibility.
// Use WithCBT(true) to enable Extended Protection.
func NewNTLMAuth(creds Credentials, opts ...NTLMAuthOption) *NTLMAuth {
	a := &NTLMAuth{creds: creds}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Name returns the authentication scheme name.
func (a *NTLMAuth) Name() string {
	return "NTLM"
}

// Transport wraps an http.RoundTripper with NTLM authentication.
// Uses github.com/Azure/go-ntlmssp for the NTLM handshake logic (connection management),
// and a custom injector to add CBT support if enabled.
func (a *NTLMAuth) Transport(base http.RoundTripper) http.RoundTripper {
	var ntlmTransport http.RoundTripper

	// If CBT is enabled, we wrap the base transport with our injector.
	// The injector sits BELOW go-ntlmssp.
	// client -> credentialsRT -> go-ntlmssp -> cbtInjector -> base
	if a.enableCBT {
		injector := &cbtInjectorRoundTripper{
			base:  base,
			creds: a.creds,
		}
		ntlmTransport = injector
	} else {
		ntlmTransport = base
	}

	// The ntlmssp.Negotiator expects credentials via SetBasicAuth on each request.
	// We wrap it with credentialsRoundTripper that adds the auth header.
	return &credentialsRoundTripper{
		creds: a.creds,
		base: ntlmssp.Negotiator{
			RoundTripper: ntlmTransport,
		},
		enableCBT: a.enableCBT,
	}
}

// credentialsRoundTripper adds Basic auth headers to each request.
// The ntlmssp.Negotiator will intercept these and convert to NTLM.
type credentialsRoundTripper struct {
	creds     Credentials
	base      http.RoundTripper
	enableCBT bool
}

func (c *credentialsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqCopy := req.Clone(req.Context())

	// Set Basic auth - ntlmssp.Negotiator will convert this to NTLM
	username := c.creds.Username
	if c.creds.Domain != "" {
		username = c.creds.Domain + "\\" + c.creds.Username
	}

	reqCopy.SetBasicAuth(username, c.creds.Password)

	return c.base.RoundTrip(reqCopy)
}

// cbtInjectorRoundTripper intercepts NTLM messages to inject Channel Binding Tokens.
// It relies on go-ntlmssp to drive the handshake state machine.
type cbtInjectorRoundTripper struct {
	base  http.RoundTripper
	creds Credentials

	// State for the handshake (protected by lock if reused, but RoundTrippers are usually per-client)
	mu            sync.Mutex
	lastChallenge []byte
	pendingCBT    *ntlmcbt.GSSChannelBindings
}

func (rt *cbtInjectorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. Inspect Request for NTLM
	authHeader := req.Header.Get("Authorization")
	upperAuth := strings.ToUpper(authHeader)

	// Check for NTLM or Negotiate prefix
	var encoded string
	var prefix string
	if strings.HasPrefix(upperAuth, "NTLM ") {
		encoded = strings.TrimSpace(authHeader[5:]) // Len("NTLM ") = 5
		prefix = "NTLM "
	} else if strings.HasPrefix(upperAuth, "NEGOTIATE ") {
		encoded = strings.TrimSpace(authHeader[10:]) // Len("Negotiate ") = 10
		prefix = "Negotiate "
	}

	if len(encoded) > 0 {
		// Try to decode
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil && len(data) > 8 && string(data[:8]) == "NTLMSSP\x00" {
			// Check message type (offset 8, 4 bytes, uint32 little endian)
			msgType := uint32(data[8]) | uint32(data[9])<<8 | uint32(data[10])<<16 | uint32(data[11])<<24

			if msgType == 3 {
				// It's a Type 3 Authenticate message!
				rt.mu.Lock()
				challenge := rt.lastChallenge
				cbt := rt.pendingCBT
				rt.mu.Unlock()

				if len(challenge) > 0 && cbt != nil {
					// Re-generate Type 3 with CBT
					username := rt.creds.Username
					if rt.creds.Domain != "" {
						username = rt.creds.Domain + "\\" + rt.creds.Username
					}

					negotiator := ntlmcbt.NewNegotiator(cbt)
					newType3, err := negotiator.ChallengeResponse(challenge, username, rt.creds.Password)
					if err == nil {
						// Replace the header use correct prefix
						req.Header.Set("Authorization", prefix+base64.StdEncoding.EncodeToString(newType3))
						slog.Debug("Injected NTLM CBT into Type 3 message", "component", "ntlm", "cbt_md5", fmt.Sprintf("%x", cbt.MD5Hash()))
					} else {
						slog.Warn("Failed to generate CBT Type 3 message", "component", "ntlm", "error", err)
					}
				}
			}
		}
	}

	// 2. Pass to Base
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// 3. Inspect Response for NTLM Challenge (Type 2)
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		// Could be "NTLM <base64>" or "Negotiate <base64>"
		upper := strings.ToUpper(wwwAuth)
		if strings.Contains(upper, "NTLM") || strings.Contains(upper, "NEGOTIATE") {
			// Extract challenge
			parts := strings.SplitN(wwwAuth, " ", 2)
			if len(parts) == 2 {
				// Verify scheme
				scheme := strings.ToUpper(parts[0])
				if scheme == "NTLM" || scheme == "NEGOTIATE" {
					challenge, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
					if err == nil && len(challenge) > 8 && string(challenge[:8]) == "NTLMSSP\x00" {
						// Validate Type 2
						msgType := uint32(challenge[8]) | uint32(challenge[9])<<8 | uint32(challenge[10])<<16 | uint32(challenge[11])<<24
						if msgType == 2 {
							// Captured Type 2!

							// Compute CBT from TLS
							var cb *ntlmcbt.GSSChannelBindings
							if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
								cb = ntlmcbt.ComputeTLSServerEndpoint(resp.TLS.PeerCertificates[0])
								slog.Debug("Captured NTLM Type 2 Challenge, computed CBT", "component", "ntlm", "cbt_md5", fmt.Sprintf("%x", cb.MD5Hash()))
							}

							rt.mu.Lock()
							rt.lastChallenge = challenge
							rt.pendingCBT = cb
							rt.mu.Unlock()
						}
					}
				}
			}
		}
	}

	return resp, nil
}
