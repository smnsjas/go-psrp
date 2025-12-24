package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// ContentTypeSOAP is the content type for SOAP 1.2 messages.
	ContentTypeSOAP = "application/soap+xml;charset=UTF-8"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 60 * time.Second
)

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
					MinVersion: tls.VersionTLS12,
				},
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
func WithTLSConfig(cfg *tls.Config) HTTPTransportOption {
	return func(t *HTTPTransport) {
		transport := t.ensureHTTPTransport()
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("transport: failed to read response: %w", err)
	}

	return respBody, nil
}

// Client returns the underlying HTTP client for advanced configuration.
func (t *HTTPTransport) Client() *http.Client {
	return t.client
}
