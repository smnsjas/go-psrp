package wsman

import (
	"errors"
	"strings"
	"testing"
)

// TestParseFault verifies SOAP fault parsing.
func TestParseFault(t *testing.T) {
	faultXML := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Body>
    <s:Fault>
      <s:Code>
        <s:Value>s:Sender</s:Value>
        <s:Subcode>
          <s:Value>w:InvalidSelectors</s:Value>
        </s:Subcode>
      </s:Code>
      <s:Reason>
        <s:Text xml:lang="en-US">The specified shell was not found.</s:Text>
      </s:Reason>
      <s:Detail>
        <p:WSManFault xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" 
                      Code="2150858843" Machine="SERVER01">
          <p:Message>Shell not found</p:Message>
        </p:WSManFault>
      </s:Detail>
    </s:Fault>
  </s:Body>
</s:Envelope>`

	fault, err := ParseFault([]byte(faultXML))
	if err != nil {
		t.Fatalf("ParseFault failed: %v", err)
	}

	if fault.Code != "s:Sender" {
		t.Errorf("Code = %q, want %q", fault.Code, "s:Sender")
	}

	if fault.Subcode != "w:InvalidSelectors" {
		t.Errorf("Subcode = %q, want %q", fault.Subcode, "w:InvalidSelectors")
	}

	if !strings.Contains(fault.Reason, "shell was not found") {
		t.Errorf("Reason = %q, want to contain 'shell was not found'", fault.Reason)
	}

	if fault.WSManCode != 2150858843 {
		t.Errorf("WSManCode = %d, want %d", fault.WSManCode, 2150858843)
	}
}

// TestParseFault_NotAFault verifies non-fault responses return nil.
func TestParseFault_NotAFault(t *testing.T) {
	normalXML := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:ShellId>test-id</rsp:ShellId>
    </rsp:Shell>
  </s:Body>
</s:Envelope>`

	fault, err := ParseFault([]byte(normalXML))
	if err != nil {
		t.Fatalf("ParseFault failed: %v", err)
	}

	if fault != nil {
		t.Errorf("expected nil fault for normal response, got %+v", fault)
	}
}

// TestFault_Error verifies the Fault error interface.
func TestFault_Error(t *testing.T) {
	fault := &Fault{
		Code:    "s:Sender",
		Subcode: "w:InvalidSelectors",
		Reason:  "Shell not found",
	}

	errStr := fault.Error()

	if !strings.Contains(errStr, "s:Sender") {
		t.Errorf("error message should contain code")
	}
	if !strings.Contains(errStr, "Shell not found") {
		t.Errorf("error message should contain reason")
	}
}

// TestIsFault verifies fault detection helper.
func TestIsFault(t *testing.T) {
	fault := &Fault{Code: "test"}
	err := error(fault)

	if !IsFault(err) {
		t.Error("IsFault should return true for Fault error")
	}

	otherErr := errors.New("other error")
	if IsFault(otherErr) {
		t.Error("IsFault should return false for non-Fault error")
	}
}

// TestFault_IsAccessDenied verifies access denied detection.
func TestFault_IsAccessDenied(t *testing.T) {
	tests := []struct {
		name     string
		fault    *Fault
		expected bool
	}{
		{
			name:     "access denied by subcode",
			fault:    &Fault{Subcode: "w:AccessDenied"},
			expected: true,
		},
		{
			name:     "access denied by WSMan code",
			fault:    &Fault{WSManCode: 5}, // ERROR_ACCESS_DENIED
			expected: true,
		},
		{
			name:     "not access denied",
			fault:    &Fault{Code: "s:Sender"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fault.IsAccessDenied(); got != tt.expected {
				t.Errorf("IsAccessDenied() = %v, want %v", got, tt.expected)
			}
		})
	}
}
