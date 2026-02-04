package auth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestCredentials_LogRedaction verifies that sensitive fields in Credentials are redacted.
func TestCredentials_LogRedaction(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	logger := slog.New(handler)

	secretPass := "SecretCredPass123!"

	creds := Credentials{
		Username: "admin",
		Password: secretPass,
		Domain:   "local",
	}

	// Log the credentials struct
	logger.Info("credentials", "creds", creds)

	logOutput := buf.String()

	if !strings.Contains(logOutput, "admin") {
		t.Errorf("Log output should contain username 'admin', got: %s", logOutput)
	}

	// Expected to FAIL initially
	if strings.Contains(logOutput, secretPass) {
		t.Errorf("SECURITY FAIL: Log output contains plaintext password! Got: %s", logOutput)
	}

	if !strings.Contains(logOutput, "REDACTED") && !strings.Contains(logOutput, "********") {
		t.Errorf("Log output should contain redaction marker, got: %s", logOutput)
	}
}
