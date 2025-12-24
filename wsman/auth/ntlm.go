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
	return ntlmssp.Negotiator{
		RoundTripper: base,
	}
}

// GetCredentials returns the credentials for the NTLM negotiator.
// This is used by the ntlmssp package to perform authentication.
func (a *NTLMAuth) GetCredentials() (string, string, string) {
	return a.creds.Domain, a.creds.Username, a.creds.Password
}
