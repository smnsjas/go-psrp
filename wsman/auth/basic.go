package auth

import (
	"encoding/base64"
	"log"
	"net/http"
	"sync"
)

// BasicAuth implements HTTP Basic authentication.
type BasicAuth struct {
	creds Credentials
}

// NewBasicAuth creates a new Basic authentication handler.
func NewBasicAuth(creds Credentials) *BasicAuth {
	return &BasicAuth{creds: creds}
}

// Name returns the authentication scheme name.
func (a *BasicAuth) Name() string {
	return "Basic"
}

// Transport wraps an http.RoundTripper with Basic authentication.
func (a *BasicAuth) Transport(base http.RoundTripper) http.RoundTripper {
	return &basicTransport{
		base:  base,
		creds: a.creds,
	}
}

// basicTransport adds Basic auth header to requests.
type basicTransport struct {
	base     http.RoundTripper
	creds    Credentials
	warnOnce sync.Once
}

// RoundTrip implements http.RoundTripper.
func (t *basicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Warn if using Basic auth over non-HTTPS (credentials are easily readable)
	if req.URL.Scheme != "https" {
		t.warnOnce.Do(func() {
			log.Printf("WARNING: Basic authentication over non-HTTPS connection to %s - credentials are not encrypted", req.URL.Host)
		})
	}

	// Clone the request to avoid mutating the original
	reqCopy := req.Clone(req.Context())

	// Build the basic auth value: base64(username:password)
	auth := t.creds.Username + ":" + t.creds.Password
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	reqCopy.Header.Set("Authorization", "Basic "+encoded)

	return t.base.RoundTrip(reqCopy)
}
