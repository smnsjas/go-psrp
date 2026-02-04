package client

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestConfig_LogRedaction verifies that sensitive fields in Config are redacted
// when logged using slog.
func TestConfig_LogRedaction(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Don't format time to make verification easier
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	logger := slog.New(handler)

	// Define a test password that we expect to be redacted
	secretPass := "SecretPassword123!"

	cfg := Config{
		Username: "testuser",
		Password: secretPass,
		Domain:   "contoso",
		Port:     5985,
	}

	// Log the config struct
	logger.Info("config loaded", "config", cfg)

	logOutput := buf.String()

	// 1. Verify username is visible (basic sanity check)
	if !strings.Contains(logOutput, "testuser") {
		t.Errorf("Log output should contain non-sensitive field 'testuser', got: %s", logOutput)
	}

	// 2. Verify password is NOT visible (Expected to FAIL initially)
	if strings.Contains(logOutput, secretPass) {
		t.Errorf("SECURITY FAIL: Log output contains plaintext password! Got: %s", logOutput)
	}

	// 3. Verify redaction marker is present (Expected to FAIL initially)
	if !strings.Contains(logOutput, "REDACTED") && !strings.Contains(logOutput, "********") {
		t.Errorf("Log output should contain redaction marker (REDACTED or ********), got: %s", logOutput)
	}
}
