package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
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

	// Bounded retry loop for multi-leg SPNEGO (supports NTLM which needs 3 legs)
	for attempt := 0; attempt < maxNegotiateRetries; attempt++ {
		// Clone request to avoid data races
		reqClone := req.Clone(req.Context())
		if bodyBytes != nil {
			reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			reqClone.ContentLength = int64(len(bodyBytes))
		}

		// Add auth header if we have a token from provider
		if clientToken != nil {
			reqClone.Header.Set("Authorization",
				fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(clientToken)))
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

		// Generate our response token
		var continueNeeded bool
		clientToken, continueNeeded, err = rt.provider.Step(req.Context(), serverToken)
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
