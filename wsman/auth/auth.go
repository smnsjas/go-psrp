// Package auth provides authentication handlers for WSMan connections.
package auth

import "net/http"

// Authenticator defines the interface for authentication handlers.
type Authenticator interface {
	// Transport wraps an http.RoundTripper with authentication.
	Transport(base http.RoundTripper) http.RoundTripper

	// Name returns the authentication scheme name.
	Name() string
}

// Credentials holds authentication credentials.
type Credentials struct {
	// Username is the user name for authentication.
	Username string

	// Password is the password for authentication.
	Password string

	// Domain is the optional domain for NTLM authentication.
	Domain string
}
