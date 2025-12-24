package wsman

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// Fault represents a WSMan SOAP fault.
type Fault struct {
	// Code is the SOAP fault code (e.g., "s:Sender", "s:Receiver").
	Code string

	// Subcode is the WSMan-specific subcode (e.g., "w:InvalidSelectors").
	Subcode string

	// Reason is the human-readable fault reason.
	Reason string

	// WSManCode is the numeric WSMan error code.
	WSManCode int

	// Machine is the machine that generated the fault.
	Machine string

	// Message is the WSMan fault message.
	Message string
}

// Error implements the error interface.
func (f *Fault) Error() string {
	var parts []string
	if f.Code != "" {
		parts = append(parts, f.Code)
	}
	if f.Subcode != "" {
		parts = append(parts, f.Subcode)
	}
	if f.Reason != "" {
		parts = append(parts, f.Reason)
	}
	if f.WSManCode != 0 {
		parts = append(parts, fmt.Sprintf("code=%d", f.WSManCode))
	}
	return "wsman fault: " + strings.Join(parts, ": ")
}

// IsAccessDenied returns true if the fault indicates access was denied.
func (f *Fault) IsAccessDenied() bool {
	if strings.Contains(f.Subcode, "AccessDenied") {
		return true
	}
	// Windows ERROR_ACCESS_DENIED
	if f.WSManCode == 5 {
		return true
	}
	return false
}

// IsShellNotFound returns true if the fault indicates the shell was not found.
func (f *Fault) IsShellNotFound() bool {
	return strings.Contains(f.Subcode, "InvalidSelectors") ||
		strings.Contains(f.Reason, "shell was not found")
}

// IsTimeout returns true if the fault indicates a timeout.
func (f *Fault) IsTimeout() bool {
	return strings.Contains(f.Subcode, "TimedOut") ||
		strings.Contains(f.Reason, "timed out")
}

// IsFault returns true if the error is a WSMan Fault.
func IsFault(err error) bool {
	var f *Fault
	return errors.As(err, &f)
}

// ParseFault parses a SOAP response and returns a Fault if present.
// Returns nil if the response does not contain a fault.
func ParseFault(data []byte) (*Fault, error) {
	// Quick check if this might be a fault
	if !strings.Contains(string(data), "<s:Fault") &&
		!strings.Contains(string(data), ":Fault") {
		return nil, nil
	}

	var env faultEnvelope
	if err := xml.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse fault: %w", err)
	}

	// Check if fault is present
	if env.Body.Fault.Code.Value == "" {
		return nil, nil
	}

	fault := &Fault{
		Code:      env.Body.Fault.Code.Value,
		Subcode:   env.Body.Fault.Code.Subcode.Value,
		Reason:    env.Body.Fault.Reason.Text,
		WSManCode: env.Body.Fault.Detail.WSManFault.Code,
		Machine:   env.Body.Fault.Detail.WSManFault.Machine,
		Message:   env.Body.Fault.Detail.WSManFault.Message,
	}

	return fault, nil
}

// CheckFault parses a response and returns an error if it contains a fault.
func CheckFault(data []byte) error {
	fault, err := ParseFault(data)
	if err != nil {
		return err
	}
	if fault != nil {
		return fault
	}
	return nil
}

// faultEnvelope is the XML structure for parsing SOAP faults.
type faultEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Fault struct {
			Code struct {
				Value   string `xml:"Value"`
				Subcode struct {
					Value string `xml:"Value"`
				} `xml:"Subcode"`
			} `xml:"Code"`
			Reason struct {
				Text string `xml:"Text"`
			} `xml:"Reason"`
			Detail struct {
				WSManFault struct {
					Code    int    `xml:"Code,attr"`
					Machine string `xml:"Machine,attr"`
					Message string `xml:"Message"`
				} `xml:"WSManFault"`
			} `xml:"Detail"`
		} `xml:"Fault"`
	} `xml:"Body"`
}
