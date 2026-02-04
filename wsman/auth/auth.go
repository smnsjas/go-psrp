// Package auth provides authentication handlers for WSMan connections.
package auth

import (
	"errors"
	"log/slog"
	"net/http"
)

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

// LogValue implements slog.LogValuer to redact sensitive fields.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Username", c.Username),
		slog.String("Password", "********"), // REDACTED
		slog.String("Domain", c.Domain),
	)
}

// Validate checks that required credential fields are populated.
// For Kerberos with ccache/keytab, password may be empty - use ValidateForKerberos instead.
func (c *Credentials) Validate() error {
	if c.Username == "" {
		return errors.New("username is required")
	}
	if c.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// ValidateForKerberos checks credentials for Kerberos auth where password is optional.
func (c *Credentials) ValidateForKerberos() error {
	if c.Username == "" {
		return errors.New("username is required")
	}
	// Password is optional for Kerberos (can use ccache/keytab)
	return nil
}
