package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// ErrUnauthorized is returned when the server responds with 401 Unauthorized.
// Use errors.Is(err, ErrUnauthorized) to check for authentication failures.
var ErrUnauthorized = errors.New("transport: authentication failed (401 Unauthorized)")

const (
	// ContentTypeSOAP is the content type for SOAP 1.2 messages.
	ContentTypeSOAP = "application/soap+xml;charset=UTF-8"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 60 * time.Second

	// defaultBufferSize is the initial size for pooled buffers.
	defaultBufferSize = 32 * 1024 // 32KB
)

// bufferPool is a pool of reusable bytes.Buffer to reduce allocations.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
	},
}

// getBuffer returns a buffer from the pool.
func getBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

// putBuffer returns a buffer to the pool after resetting it.
func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}

// readAllPooled reads from r using a pooled buffer and returns a copy of the data.
func readAllPooled(r io.Reader) ([]byte, error) {
	buf := getBuffer()
	defer putBuffer(buf)

	_, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	// Return a copy since buf will be reused
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// HTTPTransport handles HTTP/HTTPS communication for WSMan.
type HTTPTransport struct {
	client *http.Client
}

// HTTPTransportOption configures an HTTPTransport.
type HTTPTransportOption func(*HTTPTransport)

// NewHTTPTransport creates a new HTTP transport with the given options.
func NewHTTPTransport(opts ...HTTPTransportOption) *HTTPTransport {
	t := &HTTPTransport{
		client: &http.Client{
			Timeout: DefaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// MinVersion: TLS 1.2 for compatibility with older Windows servers
					// MaxVersion: Not set - allows TLS 1.3 (Go default)
					// CipherSuites: Not set for TLS 1.3 - Go manages secure defaults
					// For TLS 1.2, Go defaults to secure cipher suites
					MinVersion: tls.VersionTLS12,
				},
				// NTLM requires persistent connections for the handshake
				DisableKeepAlives: false,
				// Increase connection limits for concurrent command execution
				// Each concurrent command needs its own connection for NTLM auth
				// Default: 10 connections to support MaxConcurrentCommands=5 with headroom
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				MaxConnsPerHost:     10,
				// Longer idle timeout for NTLM sessions
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}

	for _, opt := range opts {
		opt(t)
	}

	return t
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) HTTPTransportOption {
	return func(t *HTTPTransport) {
		t.client.Timeout = d
	}
}

// WithInsecureSkipVerify configures TLS to skip certificate verification.
// WARNING: Only use this for testing. Never use in production.
func WithInsecureSkipVerify(skip bool) HTTPTransportOption {
	return func(t *HTTPTransport) {
		if skip {
			fmt.Fprintf(os.Stderr, "WARNING: TLS certificate verification disabled. This is insecure and should only be used for testing.\n")
		}
		transport := t.ensureHTTPTransport()
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		transport.TLSClientConfig.InsecureSkipVerify = skip
	}
}

// WithTLSConfig sets a custom TLS configuration.
// NOTE: MinVersion is enforced to be at least TLS 1.2 for security.
func WithTLSConfig(cfg *tls.Config) HTTPTransportOption {
	return func(t *HTTPTransport) {
		transport := t.ensureHTTPTransport()
		// Enforce minimum TLS 1.2 regardless of user config
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		transport.TLSClientConfig = cfg
	}
}

// ensureHTTPTransport ensures the client has an *http.Transport.
func (t *HTTPTransport) ensureHTTPTransport() *http.Transport {
	if t.client.Transport == nil {
		t.client.Transport = &http.Transport{}
	}
	transport, ok := t.client.Transport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
		t.client.Transport = transport
	}
	return transport
}

// Post sends a SOAP request and returns the response body.
func (t *HTTPTransport) Post(ctx context.Context, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("transport: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeSOAP)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transport: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readAllPooled(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("transport: failed to read response: %w", err)
	}

	// Check HTTP status code
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("transport: access denied (403 Forbidden)")
	}
	if resp.StatusCode >= 400 {
		// Include response body in error for debugging
		bodyPreview := string(respBody)
		if len(bodyPreview) > 3000 {
			bodyPreview = bodyPreview[:3000] + "..."
		}
		return nil, fmt.Errorf("transport: HTTP %d: %s", resp.StatusCode, bodyPreview)
	}

	return respBody, nil
}

// Client returns the underlying HTTP client for advanced configuration.
func (t *HTTPTransport) Client() *http.Client {
	return t.client
}

// CloseIdleConnections closes any idle connections in the transport.
// This is useful to force a fresh NTLM handshake for subsequent requests.
func (t *HTTPTransport) CloseIdleConnections() {
	t.client.CloseIdleConnections()
}
