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
	// Buffer the request body upfront so we can retry
	var bodyBytes []byte
	if req.Body != nil && req.ContentLength > 0 {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		// Reset body for initial request
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	// Clone request to avoid data races
	reqClone := req.Clone(req.Context())
	if bodyBytes != nil {
		reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Execute primitive request
	resp, err := rt.base.RoundTrip(reqClone)
	if err != nil {
		return nil, err
	}

	// Check for 401 and Negotiate header
	if resp.StatusCode == http.StatusUnauthorized {
		authHeader := resp.Header.Get("WWW-Authenticate")
		if strings.Contains(strings.ToLower(authHeader), "negotiate") {
			// Found Negotiate challenge.
			// Extract token if present (for mutual auth or multi-leg, though initial 401 usually has empty "Negotiate")
			var serverToken []byte
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
				// We have a token blob
				token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
				if err != nil {
					// Failed to decode token, but maybe it's just "Negotiate"
					// Log warning?
				} else {
					serverToken = token
				}
			}

			// Generate our token
			clientToken, continueNeeded, err := rt.provider.Step(req.Context(), serverToken)
			if err != nil {
				return resp, fmt.Errorf("negotiate step: %w", err)
			}

			// Retry the request with Authorization header
			// We must close the previous response body
			resp.Body.Close()

			retryReq := req.Clone(req.Context())
			retryReq.Header.Set("Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(clientToken)))
			// Use buffered body for retry
			if bodyBytes != nil {
				retryReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}

			retryResp, err := rt.base.RoundTrip(retryReq)
			if err != nil {
				return nil, err
			}

			// If generic GSSAPI loop needed (continueNeeded), we might need to handle 401 again?
			// Standard Kerberos is usually 1 round trip after 401.
			// NTLM-over-Negotiate is 3 legs (Type 1 -> Challenge -> Type 3).
			// Our interface supports this via `continueNeeded`.

			if continueNeeded && retryResp.StatusCode == http.StatusUnauthorized {
				// Recursive logic or loop needed here?
				// For now, let's assume 1-leg Kerberos which is the 90% case.
				// A robust loop implementation would handle the multi-leg NTLM-over-SPNEGO.
				// Given we already have a dedicated NTLM provider, this Negotiate provider is strictly for Kerberos initially.
			}

			return retryResp, nil
		}
	}

	return resp, nil
}
