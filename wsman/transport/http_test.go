package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewHTTPTransport verifies transport creation with default settings.
func TestNewHTTPTransport(t *testing.T) {
	tr := NewHTTPTransport()
	if tr == nil {
		t.Fatal("NewHTTPTransport returned nil")
	}
	if tr.client == nil {
		t.Error("client is nil")
	}
}

// TestHTTPTransport_WithTimeout verifies timeout configuration.
func TestHTTPTransport_WithTimeout(t *testing.T) {
	timeout := 30 * time.Second
	tr := NewHTTPTransport(WithTimeout(timeout))

	if tr.client.Timeout != timeout {
		t.Errorf("got timeout %v, want %v", tr.client.Timeout, timeout)
	}
}

// TestHTTPTransport_WithInsecureSkipVerify verifies TLS skip verify configuration.
func TestHTTPTransport_WithInsecureSkipVerify(t *testing.T) {
	tr := NewHTTPTransport(WithInsecureSkipVerify(true))

	httpTransport, ok := tr.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if httpTransport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if !httpTransport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is false, want true")
	}
}

// TestHTTPTransport_WithTLSConfig verifies custom TLS configuration.
func TestHTTPTransport_WithTLSConfig(t *testing.T) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	tr := NewHTTPTransport(WithTLSConfig(tlsCfg))

	httpTransport, ok := tr.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if httpTransport.TLSClientConfig != tlsCfg {
		t.Error("TLSClientConfig does not match provided config")
	}
}

// TestHTTPTransport_Do verifies basic request execution.
func TestHTTPTransport_Do(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify content type
		if ct := r.Header.Get("Content-Type"); ct != "application/soap+xml;charset=UTF-8" {
			t.Errorf("unexpected Content-Type: %s", ct)
		}

		// Read body
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "test-body") {
			t.Errorf("unexpected body: %s", body)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<response>ok</response>"))
	}))
	defer server.Close()

	tr := NewHTTPTransport()
	ctx := context.Background()

	resp, err := tr.Post(ctx, server.URL, []byte("<request>test-body</request>"))
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	if !strings.Contains(string(resp), "ok") {
		t.Errorf("unexpected response: %s", resp)
	}
}

// TestHTTPTransport_Do_WithContext verifies context cancellation.
func TestHTTPTransport_Do_WithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tr := NewHTTPTransport()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := tr.Post(ctx, server.URL, []byte("<request/>"))
	if err == nil {
		t.Error("expected context deadline exceeded error")
	}
}

// TestHTTPTransport_Do_Error verifies error handling for failed requests.
func TestHTTPTransport_Do_Error(t *testing.T) {
	tr := NewHTTPTransport()
	ctx := context.Background()

	// Try to connect to invalid endpoint
	_, err := tr.Post(ctx, "http://localhost:1", []byte("<request/>"))
	if err == nil {
		t.Error("expected connection error")
	}
}

// TestHTTPTransport_WithProxy verifies proxy configuration.
func TestHTTPTransport_WithProxy(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		wantNil  bool // true if Proxy should be nil (direct)
	}{
		{"empty uses defaults", "", false},
		{"direct bypasses proxy", "direct", true},
		{"explicit proxy URL", "http://proxy.example.com:8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := NewHTTPTransport(WithProxy(tt.proxyURL))

			httpTransport, ok := tr.client.Transport.(*http.Transport)
			if !ok {
				t.Fatal("transport is not *http.Transport")
			}

			if tt.proxyURL == "direct" {
				if httpTransport.Proxy != nil {
					t.Error("expected Proxy to be nil for 'direct'")
				}
			} else if tt.proxyURL != "" {
				// For explicit proxy, verify it's set
				if httpTransport.Proxy == nil {
					t.Error("expected Proxy to be set for explicit URL")
				}
			}
			// For empty string, we don't check - it uses http.ProxyFromEnvironment (default behavior)
		})
	}
}
