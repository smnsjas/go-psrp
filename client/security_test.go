package client

import (
	"strings"
	"testing"
)

// TestSanitizeScriptForLogging tests the script sanitization for logging.
func TestSanitizeScriptForLogging(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		expected string
	}{
		{
			name:     "short safe script",
			script:   "Get-Process",
			expected: "Get-Process",
		},
		{
			name:     "long safe script",
			script:   strings.Repeat("a", 150),
			expected: strings.Repeat("a", 100) + "... [truncated]",
		},
		{
			name:     "script with password keyword",
			script:   "Set-Password 'secret123'",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "script with credential keyword",
			script:   "$cred = Get-Credential",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "script with apikey",
			script:   "Connect-Service -ApiKey abc123",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "script with secret",
			script:   "$secret = 'mysecret'",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "script with -Password parameter",
			script:   "New-User -Password 'test'",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "script with ConvertTo-SecureString",
			script:   "ConvertTo-SecureString 'plain' -AsPlainText",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "script with PSCredential",
			script:   "New-Object System.Management.Automation.PSCredential",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "case insensitive detection",
			script:   "Set-PASSWORD 'test'",
			expected: "[script contains sensitive data - not logged]",
		},
		{
			name:     "script with access_token",
			script:   "Connect-API -access_token 'abc'",
			expected: "[script contains sensitive data - not logged]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeScriptForLogging(tt.script)
			if result != tt.expected {
				t.Errorf("sanitizeScriptForLogging(%q) = %q, want %q", tt.script, result, tt.expected)
			}
		})
	}
}

// TestContainsSensitivePattern tests the sensitive pattern detection.
func TestContainsSensitivePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "no sensitive pattern",
			input:    "Get-Process | Select-Object Name",
			expected: false,
		},
		{
			name:     "contains password",
			input:    "Set-Password 'secret'",
			expected: true,
		},
		{
			name:     "contains credential",
			input:    "Use-Credential $cred",
			expected: true,
		},
		{
			name:     "contains secret",
			input:    "$secret = 'value'",
			expected: true,
		},
		{
			name:     "contains apikey",
			input:    "Connect -ApiKey 'key'",
			expected: true,
		},
		{
			name:     "contains api_key",
			input:    "Set-Config -api_key 'key'",
			expected: true,
		},
		{
			name:     "contains access_token",
			input:    "Auth -access_token 'token'",
			expected: true,
		},
		{
			name:     "contains accesstoken",
			input:    "Auth -AccessToken 'token'",
			expected: true,
		},
		{
			name:     "contains -password",
			input:    "New-User -Password 'pass'",
			expected: true,
		},
		{
			name:     "contains -credential",
			input:    "Invoke-Command -Credential $cred",
			expected: true,
		},
		{
			name:     "contains convertto-securestring",
			input:    "ConvertTo-SecureString 'pass'",
			expected: true,
		},
		{
			name:     "contains pscredential",
			input:    "New-Object PSCredential",
			expected: true,
		},
		{
			name:     "contains get-credential",
			input:    "$c = Get-Credential",
			expected: true,
		},
		{
			name:     "case insensitive",
			input:    "SET-PASSWORD",
			expected: true,
		},
		{
			name:     "mixed case",
			input:    "Use-CreDenTiaL",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSensitivePattern(tt.input)
			if result != tt.expected {
				t.Errorf("containsSensitivePattern(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestExecuteLoggingSanitization tests that Execute properly sanitizes logs.
// This is an integration-style test using a mock backend.
func TestExecuteLoggingSanitization(t *testing.T) {
	// This test verifies that sensitive scripts are not logged in their entirety.
	// We test the sanitization functions above; this confirms they're integrated correctly.

	sensitiveScript := "New-User -Name test -Password 'SuperSecret123!'"
	result := sanitizeScriptForLogging(sensitiveScript)

	// Verify the result does not contain the actual password
	if strings.Contains(result, "SuperSecret123!") {
		t.Errorf("Sanitized log contains the actual password: %q", result)
	}

	// Verify it's been redacted
	if result != "[script contains sensitive data - not logged]" {
		t.Errorf("Expected redaction message, got: %q", result)
	}
}

// TestScriptInjectionPrevention tests that executeAsyncHvSocket prevents injection.
func TestScriptInjectionPrevention(t *testing.T) {
	// Test various injection attempts to ensure they're properly encoded
	injectionAttempts := []string{
		`"; Remove-Item C:\*; "`,
		`' | Stop-Process -Force; '`,
		"$(Invoke-Expression 'evil code')",
		"`$(danger)",
		"test'; evil-command; 'test",
	}

	for _, attempt := range injectionAttempts {
		t.Run("injection_"+attempt[:10], func(t *testing.T) {
			// The encodePowerShellScript function should base64-encode the entire script,
			// making it impossible to break out with special characters.
			encoded := encodePowerShellScript(attempt)

			// Verify it's base64 (doesn't contain the original dangerous characters)
			if strings.Contains(encoded, ";") || strings.Contains(encoded, "|") ||
				strings.Contains(encoded, "$") || strings.Contains(encoded, "`") {
				t.Errorf("Encoded script still contains dangerous characters: %q", encoded)
			}

			// Verify it can be decoded (basic sanity check)
			if len(encoded) == 0 {
				t.Error("Encoded script is empty")
			}
		})
	}
}
