package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCredentials verifies Credentials struct.
func TestCredentials(t *testing.T) {
	creds := Credentials{
		Username: "admin",
		Password: "secret",
		Domain:   "DOMAIN",
	}

	if creds.Username != "admin" {
		t.Errorf("Username = %q, want %q", creds.Username, "admin")
	}
	if creds.Password != "secret" {
		t.Errorf("Password = %q, want %q", creds.Password, "secret")
	}
	if creds.Domain != "DOMAIN" {
		t.Errorf("Domain = %q, want %q", creds.Domain, "DOMAIN")
	}
}

// TestBasicAuth_Name verifies the auth scheme name.
func TestBasicAuth_Name(t *testing.T) {
	auth := NewBasicAuth(Credentials{})
	if auth.Name() != "Basic" {
		t.Errorf("Name() = %q, want %q", auth.Name(), "Basic")
	}
}

// TestBasicAuth_Transport verifies the transport wrapper.
func TestBasicAuth_Transport(t *testing.T) {
	creds := Credentials{
		Username: "testuser",
		Password: "testpass",
	}
	auth := NewBasicAuth(creds)

	// Create a test server that checks auth header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			t.Error("missing Authorization header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Basic ") {
			t.Errorf("expected Basic auth, got: %s", authHeader)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Decode and verify credentials
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("failed to decode auth header: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		expected := "testuser:testpass"
		if string(decoded) != expected {
			t.Errorf("decoded credentials = %q, want %q", string(decoded), expected)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with auth transport
	client := &http.Client{
		Transport: auth.Transport(http.DefaultTransport),
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestNTLMAuth_Name verifies the auth scheme name.
func TestNTLMAuth_Name(t *testing.T) {
	auth := NewNTLMAuth(Credentials{})
	if auth.Name() != "NTLM" {
		t.Errorf("Name() = %q, want %q", auth.Name(), "NTLM")
	}
}

// TestNTLMAuth_Transport verifies NTLM transport is created.
func TestNTLMAuth_Transport(t *testing.T) {
	creds := Credentials{
		Username: "testuser",
		Password: "testpass",
		Domain:   "TESTDOMAIN",
	}
	auth := NewNTLMAuth(creds)

	transport := auth.Transport(http.DefaultTransport)
	if transport == nil {
		t.Error("Transport returned nil")
	}

	// Verify it's not the same as the base transport (it should be wrapped)
	if transport == http.DefaultTransport {
		t.Error("Transport should wrap the base transport")
	}
}

// TestAuthenticator_Interface verifies both auth types implement Authenticator.
func TestAuthenticator_Interface(_ *testing.T) {
	var _ Authenticator = NewBasicAuth(Credentials{})
	var _ Authenticator = NewNTLMAuth(Credentials{})
}
