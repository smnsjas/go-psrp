package auth

import (
	"net/http"

	"github.com/Azure/go-ntlmssp"
)

// NTLMAuth implements NTLM authentication.
type NTLMAuth struct {
	creds Credentials
}

// NewNTLMAuth creates a new NTLM authentication handler.
func NewNTLMAuth(creds Credentials) *NTLMAuth {
	return &NTLMAuth{creds: creds}
}

// Name returns the authentication scheme name.
func (a *NTLMAuth) Name() string {
	return "NTLM"
}

// Transport wraps an http.RoundTripper with NTLM authentication.
// Uses github.com/Azure/go-ntlmssp for the NTLM handshake.
func (a *NTLMAuth) Transport(base http.RoundTripper) http.RoundTripper {
	// The ntlmssp.Negotiator expects credentials via SetBasicAuth on each request.
	// We wrap it with credentialsRoundTripper that adds the auth header.
	return &credentialsRoundTripper{
		creds: a.creds,
		base: ntlmssp.Negotiator{
			RoundTripper: base,
		},
	}
}

// credentialsRoundTripper adds Basic auth headers to each request.
// The ntlmssp.Negotiator will intercept these and convert to NTLM.
type credentialsRoundTripper struct {
	creds Credentials
	base  http.RoundTripper
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
