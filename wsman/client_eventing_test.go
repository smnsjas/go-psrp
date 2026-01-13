package wsman

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/smnsjas/go-psrp/wsman/transport"
)

// MockTransport allows mocking round-trip responses
type MockTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req)
}

func TestClient_Subscribe(t *testing.T) {
	// 1. Setup Mock Transport
	mock := &MockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			// Verify Request
			body, _ := io.ReadAll(req.Body)
			bodyStr := string(body)

			if !strings.Contains(bodyStr, "http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe") {
				t.Errorf("Expected Subscribe action, got body: %s", bodyStr)
			}
			if !strings.Contains(bodyStr, "SELECT * FROM Win32_Process") {
				t.Errorf("Expected filter query")
			}

			// Return Success Response
			respXML := `
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wse="http://schemas.xmlsoap.org/ws/2004/08/eventing">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscribeResponse</a:Action>
  </s:Header>
  <s:Body>
    <wse:SubscribeResponse>
      <wse:SubscriptionManager>
        <a:Address>http://server:5985/wsman/SubscriptionManager</a:Address>
        <a:ReferenceParameters>
          <w:Identifier xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">uuid:1234-5678</w:Identifier>
        </a:ReferenceParameters>
      </wse:SubscriptionManager>
      <wse:EnumerationContext>ctx-7890</wse:EnumerationContext>
      <wse:Expires>PT10M</wse:Expires>
    </wse:SubscribeResponse>
  </s:Body>
</s:Envelope>`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(respXML)),
				Header:     make(http.Header),
			}, nil
		},
	}

	client := NewClient("http://server:5985/wsman", nil)
	tr := transport.NewHTTPTransport()
	tr.Client().Transport = mock
	client.transport = tr

	// 2. Execute
	sub, err := client.Subscribe(context.Background(), "http://resource", "SELECT * FROM Win32_Process")

	// 3. Verify
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}
	if sub.EnumerationContext != "ctx-7890" {
		t.Errorf("Expected enum context 'ctx-7890', got %s", sub.EnumerationContext)
	}
}

func TestClient_Pull_Success(t *testing.T) {
	mock := &MockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			// Verify Action is Pull
			body, _ := io.ReadAll(req.Body)
			if !strings.Contains(string(body), "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull") {
				t.Error("Expected Pull action")
			}

			// Return Events
			respXML := `
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Body>
    <wsen:PullResponse>
      <wsen:EnumerationContext>ctx-new</wsen:EnumerationContext>
      <wsen:Items>
        <EventA>DataA</EventA>
        <EventB>DataB</EventB>
      </wsen:Items>
    </wsen:PullResponse>
  </s:Body>
</s:Envelope>`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(respXML)),
			}, nil
		},
	}

	client := NewClient("http://server:5985/wsman", nil)
	tr := transport.NewHTTPTransport()
	tr.Client().Transport = mock
	client.transport = tr

	resp, err := client.Pull(context.Background(), "http://resource", "ctx-old", 10)
	if err != nil {
		t.Fatalf("Pull failed: %v", err)
	}

	if resp.EnumerationContext != "ctx-new" {
		t.Errorf("Expected new context 'ctx-new'")
	}
	// Check pure raw XML content
	raw := string(resp.Items.Raw)
	// Trimming spaces might be needed depending on unmarshal behavior, but let's check basic containment
	if !strings.Contains(raw, "<EventA>DataA</EventA>") {
		t.Errorf("Items.Raw missing EventA, got: %s", raw)
	}
}

func TestClient_Unsubscribe(t *testing.T) {
	mock := &MockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			if !strings.Contains(string(body), "Unsubscribe") {
				t.Error("Expected Unsubscribe action")
			}
			// Verify Selectors
			if !strings.Contains(string(body), "uuid:subscription-id") {
				t.Error("Expected SubscriptionId selector")
			}

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`<s:Envelope/>`)), // Empty body OK for Unsubscribe response usually
			}, nil
		},
	}

	client := NewClient("http://server:5985/wsman", nil)
	tr := transport.NewHTTPTransport()
	tr.Client().Transport = mock
	client.transport = tr

	sub := &Subscription{
		Manager: &EndpointReference{
			Address: "http://manager",
			Selectors: []Selector{
				{Name: "SubscriptionId", Value: "uuid:subscription-id"},
			},
		},
	}

	err := client.Unsubscribe(context.Background(), sub)
	if err != nil {
		t.Fatalf("Unsubscribe failed: %v", err)
	}
}
