package wsman

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestEnvelopeBuilder_BasicStructure verifies the envelope produces valid SOAP XML.
func TestEnvelopeBuilder_BasicStructure(t *testing.T) {
	env := NewEnvelope()

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	// Verify SOAP envelope structure
	if !strings.Contains(xmlStr, "Envelope") {
		t.Error("missing Envelope element")
	}
	if !strings.Contains(xmlStr, "Header") {
		t.Error("missing Header element")
	}
	if !strings.Contains(xmlStr, "Body") {
		t.Error("missing Body element")
	}
}

// TestEnvelopeBuilder_Namespaces verifies all required namespaces are declared.
func TestEnvelopeBuilder_Namespaces(t *testing.T) {
	env := NewEnvelope()

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	requiredNamespaces := []struct {
		prefix string
		uri    string
	}{
		{"xmlns:s", NsSoap},
		{"xmlns:a", NsAddressing},
		{"xmlns:w", NsWsman},
		{"xmlns:p", NsWsmanMicrosoft},
	}

	for _, ns := range requiredNamespaces {
		if !strings.Contains(xmlStr, ns.uri) {
			t.Errorf("missing namespace %s=%q", ns.prefix, ns.uri)
		}
	}
}

// TestEnvelopeBuilder_WithAction verifies setting the Action header.
func TestEnvelopeBuilder_WithAction(t *testing.T) {
	env := NewEnvelope().WithAction(ActionCreate)

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, ActionCreate) {
		t.Errorf("missing Action header value %q", ActionCreate)
	}
}

// TestEnvelopeBuilder_WithTo verifies setting the To header.
func TestEnvelopeBuilder_WithTo(t *testing.T) {
	endpoint := "https://server:5986/wsman"
	env := NewEnvelope().WithTo(endpoint)

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, endpoint) {
		t.Errorf("missing To header value %q", endpoint)
	}
}

// TestEnvelopeBuilder_WithResourceURI verifies setting the ResourceURI header.
func TestEnvelopeBuilder_WithResourceURI(t *testing.T) {
	env := NewEnvelope().WithResourceURI(ResourceURIPowerShell)

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, ResourceURIPowerShell) {
		t.Errorf("missing ResourceURI value %q", ResourceURIPowerShell)
	}
}

// TestEnvelopeBuilder_WithMessageID verifies setting the MessageID header.
func TestEnvelopeBuilder_WithMessageID(t *testing.T) {
	messageID := "uuid:test-message-id-12345"
	env := NewEnvelope().WithMessageID(messageID)

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, messageID) {
		t.Errorf("missing MessageID value %q", messageID)
	}
}

// TestEnvelopeBuilder_WithReplyTo verifies setting the ReplyTo header.
func TestEnvelopeBuilder_WithReplyTo(t *testing.T) {
	env := NewEnvelope().WithReplyTo(AddressAnonymous)

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, AddressAnonymous) {
		t.Errorf("missing ReplyTo Address value %q", AddressAnonymous)
	}
}

// TestEnvelopeBuilder_Chaining verifies method chaining works correctly.
func TestEnvelopeBuilder_Chaining(t *testing.T) {
	endpoint := "https://server:5986/wsman"
	messageID := "uuid:chained-test-id"

	env := NewEnvelope().
		WithAction(ActionCreate).
		WithTo(endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID(messageID).
		WithReplyTo(AddressAnonymous)

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	// Verify all chained values are present
	checks := []string{
		ActionCreate,
		endpoint,
		ResourceURIPowerShell,
		messageID,
		AddressAnonymous,
	}

	for _, check := range checks {
		if !strings.Contains(xmlStr, check) {
			t.Errorf("missing value after chaining: %q", check)
		}
	}
}

// TestEnvelopeBuilder_WithMaxEnvelopeSize verifies MaxEnvelopeSize header.
func TestEnvelopeBuilder_WithMaxEnvelopeSize(t *testing.T) {
	env := NewEnvelope().WithMaxEnvelopeSize(153600)

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, "153600") {
		t.Error("missing MaxEnvelopeSize value")
	}
}

// TestEnvelopeBuilder_WithOperationTimeout verifies OperationTimeout header.
func TestEnvelopeBuilder_WithOperationTimeout(t *testing.T) {
	env := NewEnvelope().WithOperationTimeout("PT60S")

	xmlBytes, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, "PT60S") {
		t.Error("missing OperationTimeout value")
	}
}
