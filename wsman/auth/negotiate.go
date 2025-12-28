package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

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
	// Buffer the body so we can retry after 401
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("buffer request body: %w", err)
		}
		req.Body.Close()
	}

	// Create a function to get fresh body reader
	getBody := func() io.ReadCloser {
		if bodyBytes == nil {
			return nil
		}
		return io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// First request
	firstReq := req.Clone(req.Context())
	firstReq.Body = getBody()

	resp, err := rt.base.RoundTrip(firstReq)
	if err != nil {
		return nil, err
	}

	// Check for 401 and Negotiate header
	if resp.StatusCode == http.StatusUnauthorized {
		authHeader := resp.Header.Get("WWW-Authenticate")
		if strings.Contains(strings.ToLower(authHeader), "negotiate") {
			// Found Negotiate challenge.
			// Extract token if present (for mutual auth)
			var serverToken []byte
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
				token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
				if err == nil {
					serverToken = token
				}
			}

			// Generate our token
			clientToken, continueNeeded, err := rt.provider.Step(req.Context(), serverToken)
			if err != nil {
				return resp, fmt.Errorf("negotiate step: %w", err)
			}

			// Close previous response body
			resp.Body.Close()

			// Retry with fresh body and Authorization header
			retryReq := req.Clone(req.Context())
			retryReq.Body = getBody()
			retryReq.ContentLength = int64(len(bodyBytes))
			retryReq.Header.Set("Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(clientToken)))

			retryResp, err := rt.base.RoundTrip(retryReq)
			if err != nil {
				return nil, err
			}

			// Handle multi-leg if needed
			if continueNeeded && retryResp.StatusCode == http.StatusUnauthorized {
				// Multi-leg SPNEGO (e.g., NTLM over Negotiate)
				// For now, return as-is; Kerberos is typically 1-leg
			}

			return retryResp, nil
		}
	}

	return resp, nil
}
