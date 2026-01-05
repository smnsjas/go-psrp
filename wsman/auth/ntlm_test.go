package auth

import (
	"net/http"
	"testing"
)

func TestNTLMAuth_RoundTrip(t *testing.T) {
	creds := Credentials{
		Username: "user",
		Password: "pass",
		Domain:   "domain",
	}

	auth := NewNTLMAuth(creds)
	if auth.Name() != "NTLM" {
		t.Errorf("Name() = %s; want NTLM", auth.Name())
	}

	// Mock the base transport (which corresponds to ntlmssp.Negotiator)
	mockBase := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			// Verify that Basic auth header is set correctly
			// Format: domain\user : pass
			u, p, ok := req.BasicAuth()
			if !ok {
				t.Error("Basic auth not set on request passed to base transport")
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

	// We can't easily inject mockBase into auth.Transport() because it hardcodes ntlmssp.Negotiator.
	// But auth.Transport(base) returns a wrapper that wraps ntlmssp.Negotiator{RoundTripper: base}.
	// Wait, credentialsRoundTripper wraps ntlmssp.Negotiator.
	// And ntlmssp.Negotiator calls its RoundTripper.
	// So if we pass mockBase to Transport(), it ends up being the RoundTripper of ntlmssp.Negotiator.
	// But credentialsRoundTripper logic is:
	// 1. Sets Basic Auth on req.
	// 2. Calls ntlmssp.Negotiator.RoundTrip(req).
	// 3. ntlmssp.Negotiator consumes Basic Auth and does NTLM.
	// 4. ntlmssp.Negotiator calls mockBase.RoundTrip(req) ONLY if NTLM handshake done?
	// Or mocked base sees the REQUEST after ntlmssp processing?
	//
	// If ntlmssp.Negotiator is working, it strips Basic auth?
	// Or does it pass it through?
	//
	// Actually, we want to test `credentialsRoundTripper` logic directly if possible.
	// But it is unexported.
	// However, `auth.Transport()` returns `http.RoundTripper` interface.
	// We can inspect the returned object via reflection or just rely on integration behavior?

	// If we run `rt.RoundTrip(req)`, it goes:
	// wrapper -> ntlmssp -> mockBase.
	// We want to verifying wrapper sets Basic Auth.
	// But ntlmssp consumes it.

	// Alternative: Inspect structure of returned transport via unsafeprinter/reflection
	// or assume code is correct if we can't mock ntlmssp.Negotiator struct itself (embedded value).

	// However, since `ntlm_test.go` is in package `auth`, we CAN access `credentialsRoundTripper`!
	// So we can instantiate it directly with a mock base that captures request!

	wrapper := &credentialsRoundTripper{
		creds: creds,
		base:  mockBase, // Here we inject mockBase AS ntlmssp replacement!
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err := wrapper.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
}
