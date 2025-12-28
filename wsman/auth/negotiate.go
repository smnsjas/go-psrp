package auth

import (
	"encoding/base64"
	"fmt"
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
	// 1. Try the request optimistically (or if we already have a context, maybe we should reuse?)
	// For simple Kerberos (1-leg), we often need to present the ticket immediately if we know we are doing Kerberos.
	// But standard SPNEGO starts with an optimistic Request -> 401Negotiate -> Token Exchange.
	// OR we can start the token generation immediately if we want to be "Optimistic Kerberos".

	// Let's stick to the standard "Wait for 401" pattern or "Optimistic" if configured?
	// Actually, many Kerberos clients (like curl --negotiate) wait for the 401 challenge first.
	// BUT, if we know we need Kerberos, we can just start.
	// Let's implement the standard: Request -> 401 -> Negotiate.

	// Clone request to avoid data races
	reqClone := req.Clone(req.Context())

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
