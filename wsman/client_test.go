package wsman

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smnsjas/go-psrp/wsman/transport"
)

// TestClient_Create verifies the Create operation builds correct SOAP envelope.
func TestClient_Create(t *testing.T) {
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)

		// Return a mock Create response with EndpointReference
		response := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Body>
    <w:ResourceCreated>
      <a:Address>http://localhost:5985/wsman</a:Address>
      <a:ReferenceParameters>
        <w:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.PowerShell</w:ResourceURI>
        <w:SelectorSet>
          <w:Selector Name="ShellId">11111111-1111-1111-1111-111111111111</w:Selector>
        </w:SelectorSet>
      </a:ReferenceParameters>
    </w:ResourceCreated>
  </s:Body>
</s:Envelope>`
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())

	epr, err := client.Create(context.Background(), nil, "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify EPR is valid
	if epr.Address == "" {
		t.Error("EPR Address is empty")
	}
	if epr.ResourceURI != ResourceURIPowerShell {
		t.Errorf("EPR ResourceURI = %q, want %q", epr.ResourceURI, ResourceURIPowerShell)
	}

	// Verify request contained correct action
	if !strings.Contains(receivedBody, ActionCreate) {
		t.Errorf("request missing Create action")
	}

	// Verify request contained PowerShell resource URI
	if !strings.Contains(receivedBody, ResourceURIPowerShell) {
		t.Errorf("request missing PowerShell resource URI")
	}
}

func dummyEPR() *EndpointReference {
	return &EndpointReference{
		Address:     "http://localhost:5985/wsman",
		ResourceURI: ResourceURIPowerShell,
		Selectors: []Selector{
			{Name: "ShellId", Value: "test-shell-id"},
		},
	}
}

// TestClient_Command verifies the Command operation.
func TestClient_Command(t *testing.T) {
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)

		response := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Body>
    <rsp:CommandResponse>
      <rsp:CommandId>22222222-2222-2222-2222-222222222222</rsp:CommandId>
    </rsp:CommandResponse>
  </s:Body>
</s:Envelope>`
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())

	commandID, err := client.Command(context.Background(), dummyEPR(), "", "")
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	if commandID != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("commandID = %q, want %q", commandID, "22222222-2222-2222-2222-222222222222")
	}

	if !strings.Contains(receivedBody, ActionCommand) {
		t.Errorf("request missing Command action")
	}

	if !strings.Contains(receivedBody, "test-shell-id") {
		t.Errorf("request missing shell ID selector")
	}
}

// TestClient_Send verifies the Send operation.
func TestClient_Send(t *testing.T) {
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)

		response := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:SendResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>
  </s:Body>
</s:Envelope>`
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())

	err := client.Send(context.Background(), dummyEPR(), "command-id", "stdin", []byte("test-data"))
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if !strings.Contains(receivedBody, ActionSend) {
		t.Errorf("request missing Send action")
	}

	// Data should be base64 encoded in the stream
	if !strings.Contains(receivedBody, "Stream") {
		t.Errorf("request missing Stream element")
	}
}

// TestClient_Receive verifies the Receive operation.
func TestClient_Receive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return mock receive response with base64 encoded data
		response := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Body>
    <rsp:ReceiveResponse>
      <rsp:Stream Name="stdout" CommandId="cmd-id">dGVzdC1kYXRh</rsp:Stream>
      <rsp:CommandState CommandId="cmd-id" State="Running"/>
    </rsp:ReceiveResponse>
  </s:Body>
</s:Envelope>`
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())

	result, err := client.Receive(context.Background(), dummyEPR(), "command-id")
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	// "dGVzdC1kYXRh" decodes to "test-data"
	if string(result.Stdout) != "test-data" {
		t.Errorf("stdout = %q, want %q", string(result.Stdout), "test-data")
	}
}

// TestClient_Signal verifies the Signal operation.
func TestClient_Signal(t *testing.T) {
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)

		response := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>
  </s:Body>
</s:Envelope>`
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())

	err := client.Signal(context.Background(), dummyEPR(), "command-id", SignalTerminate)
	if err != nil {
		t.Fatalf("Signal failed: %v", err)
	}

	if !strings.Contains(receivedBody, ActionSignal) {
		t.Errorf("request missing Signal action")
	}

	if !strings.Contains(receivedBody, SignalTerminate) {
		t.Errorf("request missing terminate signal code")
	}
}

// TestClient_Delete verifies the Delete operation.
func TestClient_Delete(t *testing.T) {
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)

		response := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body/>
</s:Envelope>`
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())

	err := client.Delete(context.Background(), dummyEPR())
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if !strings.Contains(receivedBody, ActionDelete) {
		t.Errorf("request missing Delete action")
	}
}

// Suppress unused import warning for xml package.
var _ = xml.Name{}
