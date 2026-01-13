package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/smnsjas/go-psrp/wsman/transport"
)

// MockHTTPTransport for client package tests
type MockHTTPTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req)
}

func (m *MockHTTPTransport) CloseIdleConnections() {}
func (m *MockHTTPTransport) Client() *http.Client  { return &http.Client{} }

func TestSubscribe_Lifecycle(t *testing.T) {
	// This test simulates the full loop: Subscribe -> Pull (Event) -> Pull (Empty) -> Close (Unsubscribe)

	step := 0
	mock := &MockHTTPTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			bodyBytes, _ := io.ReadAll(req.Body)
			body := string(bodyBytes)

			// Helper to return success XML
			returnOK := func(respBody string) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(respBody)),
				}, nil
			}

			if strings.Contains(body, "Subscribe") {
				return returnOK(`
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wse="http://schemas.xmlsoap.org/ws/2004/08/eventing">
  <s:Body>
    <wse:SubscribeResponse>
      <wse:EnumerationContext>ctx-1</wse:EnumerationContext>
      <wse:SubscriptionManager>
          <a:Address xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://mgr</a:Address>
      </wse:SubscriptionManager>
    </wse:SubscribeResponse>
  </s:Body>
</s:Envelope>`)
			} else if strings.Contains(body, "Pull") {
				step++
				if step == 1 {
					// First pull: Return an event
					return returnOK(`
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Body>
    <wsen:PullResponse>
      <wsen:EnumerationContext>ctx-2</wsen:EnumerationContext>
      <wsen:Items><Event>Hello</Event></wsen:Items>
    </wsen:PullResponse>
  </s:Body>
</s:Envelope>`)
				} else {
					// Subsequent pulls: Empty (wait)
					return returnOK(`
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Body>
    <wsen:PullResponse>
      <wsen:EnumerationContext>ctx-2</wsen:EnumerationContext>
      <wsen:Items/>
    </wsen:PullResponse>
  </s:Body>
</s:Envelope>`)
				}
			} else if strings.Contains(body, "Unsubscribe") {
				return returnOK(`<s:Envelope/>`)
			}

			return nil, fmt.Errorf("unexpected request: %s", body)
		},
	}

	cfg := Config{
		Username: "user",
		Password: "pass",
		AuthType: AuthBasic,
	}
	c, err := New("http://server", cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Inject Mock Transport
	// Create a real HTTPTransport wrapping our mock RoundTripper
	tr := transport.NewHTTPTransport()
	// We can't insert RoundTripper into transport directly via exported methods easily usually?
	// transport.NewHTTPTransport creates a client.
	// We need to inject our mock as the transport of the client?
	// transport.Client().Transport = mock
	tr.Client().Transport = mock

	// Set on wsman client
	c.wsman.SetTransport(tr)

	// Subscribe with VERY fast poll interval
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub, err := c.Subscribe(ctx, "query", SubscribeOptions{PollInterval: 10 * time.Millisecond})
	if err != nil {
		// If Subscribe failed, print why
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	// Wait for 1st event
	select {
	case ev := <-sub.Events:
		if !strings.Contains(string(ev), "Hello") {
			t.Errorf("Expected 'Hello' event, got %s", ev)
		}
	case err := <-sub.Errors:
		t.Errorf("Unexpected error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for event")
	}

	// Wait for clean close
	err = sub.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestSubscribe_InputValidation(t *testing.T) {
	cfg := Config{
		Username: "user",
		Password: "pass",
		AuthType: AuthBasic,
	}
	c, _ := New("http://server", cfg)

	// Huge query
	hugeQuery := strings.Repeat("A", 20000)
	_, err := c.Subscribe(context.Background(), hugeQuery)
	if err == nil {
		t.Error("Expected error for huge query, got nil")
	} else if !strings.Contains(err.Error(), "query too long") {
		t.Errorf("Expected 'query too long' error, got: %v", err)
	}
}
