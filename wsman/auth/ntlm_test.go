package auth

import (
	"net/http"
	"testing"
)

func TestNTLMAuth_Name_WithCBT(t *testing.T) {
	creds := Credentials{
		Username: "user",
		Password: "pass",
		Domain:   "domain",
	}

	// Test without CBT
	auth := NewNTLMAuth(creds)
	if auth.Name() != "NTLM" {
		t.Errorf("Name() = %s; want NTLM", auth.Name())
	}

	// Test with CBT enabled
	authCBT := NewNTLMAuth(creds, WithCBT(true))
	if authCBT.Name() != "NTLM" {
		t.Errorf("Name() with CBT = %s; want NTLM", authCBT.Name())
	}
}

func TestNTLMAuth_Transport_ReturnsRoundTripper(t *testing.T) {
	creds := Credentials{
		Username: "user",
		Password: "pass",
	}

	auth := NewNTLMAuth(creds)
	base := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200}, nil
		},
	}

	rt := auth.Transport(base)
	if rt == nil {
		t.Error("Transport() returned nil")
	}
}

func TestNTLMAuth_WithCBT_Option(t *testing.T) {
	creds := Credentials{}

	// Default should have CBT disabled
	auth := NewNTLMAuth(creds)
	if auth.enableCBT {
		t.Error("CBT should be disabled by default")
	}

	// With CBT enabled
	authCBT := NewNTLMAuth(creds, WithCBT(true))
	if !authCBT.enableCBT {
		t.Error("CBT should be enabled when WithCBT(true) is passed")
	}

	// With CBT explicitly disabled
	authNoCBT := NewNTLMAuth(creds, WithCBT(false))
	if authNoCBT.enableCBT {
		t.Error("CBT should be disabled when WithCBT(false) is passed")
	}
}

func TestCredentialsRoundTripper_SetsBasicAuth(t *testing.T) {
	creds := Credentials{
		Username: "user",
		Password: "pass",
		Domain:   "domain",
	}

	mockBase := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			// Verify that Basic auth header is set correctly
			u, p, ok := req.BasicAuth()
			if !ok {
				t.Error("Basic auth not set on request")
			}
			expectedUser := "domain\\user"
			if u != expectedUser {
				t.Errorf("Username = %s; want %s", u, expectedUser)
			}
			if p != "pass" {
				t.Errorf("Password = %s; want pass", p)
			}
			return &http.Response{StatusCode: 200}, nil
		},
	}

	wrapper := &credentialsRoundTripper{
		creds: creds,
		base:  mockBase,
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err := wrapper.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
}
