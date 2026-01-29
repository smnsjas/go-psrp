package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// MockSecurityProvider for testing Negotiate logic
type MockSecurityProvider struct {
	StepFunc func(ctx context.Context, serverToken []byte) (clientToken []byte, continueNeeded bool, err error)
}

func (m *MockSecurityProvider) Step(ctx context.Context, serverToken []byte) (clientToken []byte, continueNeeded bool, err error) {
	if m.StepFunc != nil {
		return m.StepFunc(ctx, serverToken)
	}
	return nil, false, nil
}

func (m *MockSecurityProvider) Wrap(data []byte) ([]byte, error) {
	return data, nil // Pass-through for tests
}

func (m *MockSecurityProvider) Unwrap(data []byte) ([]byte, error) {
	return data, nil // Pass-through for tests
}

func (m *MockSecurityProvider) Close() error {
	return nil
}

func (m *MockSecurityProvider) Complete() bool {
	return false
}

func (m *MockSecurityProvider) ProcessResponse(ctx context.Context, authHeader string) error {
	return nil
}

func TestNegotiateAuth_Name(t *testing.T) {
	auth := NewNegotiateAuth(&MockSecurityProvider{})
	if auth.Name() != "Negotiate" {
		t.Errorf("Name() = %s; want Negotiate", auth.Name())
	}
}

// MockRoundTripper captures requests and returns canned responses
type MockRoundTripper struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.RoundTripFunc != nil {
		return m.RoundTripFunc(req)
	}
	return &http.Response{StatusCode: 200}, nil
}

func TestNegotiateRoundTrip_Success_NoChallenge(t *testing.T) {
	// Simple case: server accepts request immediately
	transport := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("success")),
			}, nil
		},
	}

	auth := NewNegotiateAuth(&MockSecurityProvider{})
	rt := auth.Transport(transport)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d; want 200", resp.StatusCode)
	}
}

func TestNegotiateRoundTrip_ChallengeResponse(t *testing.T) {
	// Scenario:
	// 1. Client sends request (no auth)
	// 2. Server sends 401 + Negotiate header
	// 3. Client calls Step, generates token "client-token-1"
	// 4. Client sends request + Authorization: Negotiate client-token-1
	// 5. Server sends 200 (Success)

	stepCalled := 0
	provider := &MockSecurityProvider{
		StepFunc: func(ctx context.Context, serverToken []byte) ([]byte, bool, error) {
			stepCalled++
			if len(serverToken) > 0 {
				t.Error("First step should have empty server token")
			}
			return []byte("client-token-1"), true, nil
		},
	}

	// NOTE: This test uses a GET with a body to TRIGGER the "Handshake First" logic.
	// We expect the client to send a proactive auth header on the first request because Step() is called.
	requests := 0
	transport := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			requests++
			auth := req.Header.Get("Authorization")

			if requests == 1 {
				// First request: Handshake First (Empty Body) + Proactive Auth Token
				// Because Step() generates a token immediately in this mock.
				expected := "Negotiate " + base64.StdEncoding.EncodeToString([]byte("client-token-1"))
				if auth != expected {
					// NOTE: If the real code decided NOT to send token on first empty handshake, this would be empty.
					// But `roundTripInternal` calls `Step` if not complete. `Step` mock returns token.
					// So we expect token.
					t.Errorf("Req 1: auth header mismatch\ngot:  %s\nwant: %s", auth, expected)
				}
				// Return 401 to challenge (even though we sent token, server might want mutual auth or reject first)
				// Or server accepts?
				// Classic flow: Client sends token -> Server says OK or Continue.
				// Let's verify what the code does. It expects to continue until 'Complete'.
				return &http.Response{
					StatusCode: 401,
					Header:     http.Header{"Www-Authenticate": []string{"Negotiate"}},
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}

			if requests == 2 {
				// Second request: Retry?
				// If first was 401, we retry.
				// Code should produce token again? Or Step continues?
				// Our mock Step just returns "client-token-1" always.
				expected := "Negotiate " + base64.StdEncoding.EncodeToString([]byte("client-token-1"))
				if auth != expected {
					t.Errorf("Req 2: auth header mismatch\ngot:  %s\nwant: %s", auth, expected)
				}
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("success")),
				}, nil
			}

			// Third request: The REAL body request (since request 2 was the handshake retry success)
			if requests == 3 {
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("success")),
				}, nil
			}

			return nil, errors.New("unexpected request count")
		},
	}

	auth := NewNegotiateAuth(provider)
	rt := auth.Transport(transport)

	req, _ := http.NewRequest("GET", "http://example.com", strings.NewReader("body")) // Trigger Handshake First
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Final status = %d; want 200", resp.StatusCode)
	}
	if stepCalled != 3 {
		t.Errorf("Step called %d times; want 3", stepCalled)
	}
}

func TestNegotiateRoundTrip_WithBody(t *testing.T) {
	provider := &MockSecurityProvider{
		StepFunc: func(ctx context.Context, serverToken []byte) ([]byte, bool, error) {
			return []byte("token"), true, nil
		},
	}

	requests := 0
	transport := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			requests++
			// Check if body is present and readable
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body error: %v", err)
			}

			// With Handshake First logic, the first 1-2 requests might have empty bodies to establish context.
			// Only the final request (when auth complete) should have "request-body".

			if string(body) == "" {
				// Handshake request
				if requests > 3 {
					t.Errorf("Req %d unexpected empty body (looping?)", requests)
				}
			} else {
				// Payload request
				if string(body) != "request-body" {
					t.Errorf("Req %d body = %s; want request-body", requests, string(body))
				}
			}

			if requests == 1 {
				// First Handshake attempt -> 401
				return &http.Response{
					StatusCode: 401,
					Header:     http.Header{"Www-Authenticate": []string{"Negotiate"}},
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
			// Req 2 (Retry Handshake -> 200) -> Handshake Complete
			// Req 3 (Real Body -> 200)
			return &http.Response{StatusCode: 200}, nil
		},
	}

	auth := NewNegotiateAuth(provider)
	rt := auth.Transport(transport)

	// Must pass body that can be read
	req, _ := http.NewRequest("POST", "http://example.com", strings.NewReader("request-body"))
	req.ContentLength = 12
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
}

func TestNegotiateRoundTrip_MaxRetries(t *testing.T) {
	provider := &MockSecurityProvider{
		StepFunc: func(ctx context.Context, serverToken []byte) ([]byte, bool, error) {
			return []byte("token"), true, nil
		},
	}

	transport := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 401,
				Header:     http.Header{"Www-Authenticate": []string{"Negotiate dG9rZW4="}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	}

	auth := NewNegotiateAuth(provider)
	rt := auth.Transport(transport)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err := rt.RoundTrip(req)
	if err == nil {
		t.Error("Expected error after max retries, got nil")
	} else if !strings.Contains(err.Error(), "failed after 5 attempts") {
		t.Errorf("Error = %v; want max retries error", err)
	}
}
