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

func (m *MockSecurityProvider) Close() error {
	return nil
}

func (m *MockSecurityProvider) Complete() bool {
	return false
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

	requests := 0
	transport := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			requests++
			auth := req.Header.Get("Authorization")

			if requests == 1 {
				// First request: expect no auth (or check emptiness)
				if auth != "" {
					t.Errorf("Req 1: unexpected auth header: %s", auth)
				}
				return &http.Response{
					StatusCode: 401,
					Header:     http.Header{"Www-Authenticate": []string{"Negotiate"}},
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}

			if requests == 2 {
				// Second request: expect token
				expected := "Negotiate " + base64.StdEncoding.EncodeToString([]byte("client-token-1"))
				if auth != expected {
					t.Errorf("Req 2: auth header mismatch\ngot:  %s\nwant: %s", auth, expected)
				}
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

	req, _ := http.NewRequest("GET", "http://example.com", strings.NewReader("body")) // Use body to test rewind logic
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Final status = %d; want 200", resp.StatusCode)
	}
	if stepCalled != 1 {
		t.Errorf("Step called %d times; want 1", stepCalled)
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
			if string(body) != "request-body" {
				t.Errorf("Req %d body = %s; want request-body", requests, string(body))
			}

			if requests == 1 {
				return &http.Response{
					StatusCode: 401,
					Header:     http.Header{"Www-Authenticate": []string{"Negotiate"}},
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
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
				Header:     http.Header{"Www-Authenticate": []string{"Negotiate token"}},
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
