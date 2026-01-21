package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
)

// maxNegotiateRetries is the maximum number of authentication attempts.
// This prevents infinite loops from malicious servers.
const maxNegotiateRetries = 5

// NegotiateAuth implements SPNEGO authentication using a pluggable SecurityProvider.
type NegotiateAuth struct {
	provider SecurityProvider
}

// NewNegotiateAuth creates a new Negotiate authenticator.
func NewNegotiateAuth(provider SecurityProvider) *NegotiateAuth {
	return &NegotiateAuth{
		provider: provider,
	}
}

// Name returns the scheme name.
func (a *NegotiateAuth) Name() string {
	return "Negotiate"
}

// Transport wraps the base transport with Negotiate authentication logic.
func (a *NegotiateAuth) Transport(base http.RoundTripper) http.RoundTripper {
	return &negotiateRoundTripper{
		base:     base,
		provider: a.provider,
	}
}

type negotiateRoundTripper struct {
	base     http.RoundTripper
	provider SecurityProvider
}

// contextKey is a context key type.
type contextKey string

// ContextKeyChannelBindings is the context key for Channel Binding Token (CBT) data.
const ContextKeyChannelBindings = contextKey("ChannelBindings")

func getCBTHash(state *tls.ConnectionState) []byte {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]
	// Use hash algorithm based on certificate signature algorithm per RFC 5929
	var h hash.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		h = sha256.New()
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h = sha512.New384()
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h = sha512.New()
	default:
		// Default to SHA256 for older algos (MD5, SHA1) or unknown
		h = sha256.New()
	}

	h.Write(cert.Raw)
	return h.Sum(nil)
}

func (rt *negotiateRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Buffer the request body upfront so we can retry
	var bodyBytes []byte
	if req.Body != nil && req.ContentLength > 0 {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		_ = req.Body.Close() // Error intentionally ignored; body already read
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		// Reset body for initial request
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	var resp *http.Response
	var serverToken []byte
	var clientToken []byte
	var cbtData []byte

	// Capture TLS connection state
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				if tlsConn, ok := info.Conn.(*tls.Conn); ok {
					state := tlsConn.ConnectionState()
					cbtData = getCBTHash(&state)
				}
			} else if info.Conn == nil {
				fmt.Printf("WARN: GotConn info.Conn is nil\n")
			}
		},
	}
	ctx := httptrace.WithClientTrace(req.Context(), trace)

	// Traditional challenge-response flow:
	// 1. First request without token
	// 2. Get 401 + Negotiate challenge
	// 3. Generate token and send
	// 4. Get 200 (or mutual auth response)

	// Bounded retry loop for multi-leg SPNEGO (supports NTLM which needs 3 legs)
	for attempt := 0; attempt < maxNegotiateRetries; attempt++ {
		// Clone request to avoid data races and inject CBT data if available
		reqCtx := ctx
		if len(cbtData) > 0 {
			reqCtx = context.WithValue(reqCtx, ContextKeyChannelBindings, cbtData)
		}
		reqClone := req.Clone(reqCtx)
		if bodyBytes != nil {
			reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			reqClone.ContentLength = int64(len(bodyBytes))
		}

		// Add auth header if we have a token from provider
		if clientToken != nil {
			authHeaderValue := fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(clientToken))
			fmt.Printf("DEBUG: Sending Authorization header length=%d, token_b64_len=%d\n",
				len(authHeaderValue), len(base64.StdEncoding.EncodeToString(clientToken)))
			fmt.Printf("DEBUG: Authorization header (first 200 chars): %.200s\n", authHeaderValue)
			reqClone.Header.Set("Authorization", authHeaderValue)
		}

		// Execute request
		var err error
		resp, err = rt.base.RoundTrip(reqClone)
		if err != nil {
			return nil, err
		}

		// Success - return response
		if resp.StatusCode != http.StatusUnauthorized {
			return resp, nil
		}

		// Check for Negotiate header
		authHeader := resp.Header.Get("WWW-Authenticate")
		if !strings.Contains(strings.ToLower(authHeader), "negotiate") {
			// Not a Negotiate challenge, return as-is
			return resp, nil
		}

		// Extract server token if present
		serverToken = nil
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			token, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
			if decodeErr == nil {
				serverToken = token
			}
			// Decode errors ignored: server may just send "Negotiate" without token
		}

		// If we already sent a token and server returns bare "Negotiate", auth was rejected
		if attempt > 0 && serverToken == nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("negotiate authentication rejected: server returned 401 with bare Negotiate after receiving our token (possible SPN mismatch or server doesn't accept Kerberos)")
		}

		// Generate our response token
		var continueNeeded bool
		// Context for Step needs to contain the CBT data we captured
		stepCtx := req.Context()
		if len(cbtData) > 0 {
			stepCtx = context.WithValue(stepCtx, ContextKeyChannelBindings, cbtData)
		}
		clientToken, continueNeeded, err = rt.provider.Step(stepCtx, serverToken)
		if err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("negotiate step failed: %w", err)
		}

		// Close response body before retry
		_ = resp.Body.Close()

		// If no more steps needed and we already sent a token, we're done
		if !continueNeeded && attempt > 0 {
			// Auth complete but server still returning 401 - fail
			break
		}
	}

	return nil, fmt.Errorf("negotiate authentication failed after %d attempts", maxNegotiateRetries)
}
