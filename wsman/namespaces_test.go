package wsman

import (
	"testing"
)

// TestNamespaceConstants verifies all required WS-Management namespace constants are defined.
func TestNamespaceConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		// SOAP 1.2
		{
			name:     "SOAP Envelope",
			constant: NsSoap,
			expected: "http://www.w3.org/2003/05/soap-envelope",
		},
		// WS-Addressing
		{
			name:     "WS-Addressing",
			constant: NsAddressing,
			expected: "http://schemas.xmlsoap.org/ws/2004/08/addressing",
		},
		// WS-Management (DMTF)
		{
			name:     "WS-Management (DMTF)",
			constant: NsWsman,
			expected: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
		},
		// WS-Management (Microsoft)
		{
			name:     "WS-Management (Microsoft)",
			constant: NsWsmanMicrosoft,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
		},
		// Windows Shell
		{
			name:     "Windows Shell",
			constant: NsShell,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
		},
		// WS-Transfer
		{
			name:     "WS-Transfer",
			constant: NsTransfer,
			expected: "http://schemas.xmlsoap.org/ws/2004/09/transfer",
		},
		// WS-Enumeration
		{
			name:     "WS-Enumeration",
			constant: NsEnumeration,
			expected: "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
		},
		// XML Schema Instance
		{
			name:     "XML Schema Instance",
			constant: NsXsi,
			expected: "http://www.w3.org/2001/XMLSchema-instance",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("got %q, want %q", tt.constant, tt.expected)
			}
		})
	}
}

// TestActionURIConstants verifies WSMan action URI constants.
func TestActionURIConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		// Transfer operations
		{
			name:     "Create",
			constant: ActionCreate,
			expected: "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
		},
		{
			name:     "CreateResponse",
			constant: ActionCreateResponse,
			expected: "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse",
		},
		{
			name:     "Delete",
			constant: ActionDelete,
			expected: "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
		},
		{
			name:     "DeleteResponse",
			constant: ActionDeleteResponse,
			expected: "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse",
		},
		// Shell operations
		{
			name:     "Command",
			constant: ActionCommand,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
		},
		{
			name:     "CommandResponse",
			constant: ActionCommandResponse,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse",
		},
		{
			name:     "Send",
			constant: ActionSend,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send",
		},
		{
			name:     "Receive",
			constant: ActionReceive,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
		},
		{
			name:     "ReceiveResponse",
			constant: ActionReceiveResponse,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse",
		},
		{
			name:     "Signal",
			constant: ActionSignal,
			expected: "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("got %q, want %q", tt.constant, tt.expected)
			}
		})
	}
}

// TestResourceURIConstants verifies PSRP resource URI constants.
func TestResourceURIConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "PowerShell",
			constant: ResourceURIPowerShell,
			expected: "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("got %q, want %q", tt.constant, tt.expected)
			}
		})
	}
}

// TestAnonymousAddress verifies the WS-Addressing anonymous address.
func TestAnonymousAddress(t *testing.T) {
	expected := "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
	if AddressAnonymous != expected {
		t.Errorf("AddressAnonymous = %q, want %q", AddressAnonymous, expected)
	}
}
