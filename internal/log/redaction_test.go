package log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactingHandler(t *testing.T) {
	tests := []struct {
		name     string
		attrs    []slog.Attr
		expected map[string]string
	}{
		{
			name: "sensitive keys are redacted",
			attrs: []slog.Attr{
				slog.String("password", "secret123"),
				slog.String("api_token", "abcdef"),
				slog.String("username", "admin"), // safe
			},
			expected: map[string]string{
				"password":  "[REDACTED]",
				"api_token": "[REDACTED]",
				"username":  "admin",
			},
		},
		{
			name: "case insensitive matching",
			attrs: []slog.Attr{
				slog.String("UserPassword", "secret"),
				slog.String("AUTH_KEY", "xyz"),
			},
			expected: map[string]string{
				"UserPassword": "[REDACTED]",
				"AUTH_KEY":     "[REDACTED]",
			},
		},
		{
			name: "nested groups are redacted",
			attrs: []slog.Attr{
				slog.Group("credentials",
					slog.String("password", "hidden"),
					slog.String("user", "visible"),
				),
			},
			expected: map[string]string{
				"credentials.password": "[REDACTED]",
				"credentials.user":     "visible",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := NewRedactingHandler(slog.NewJSONHandler(&buf, nil))
			logger := slog.New(h)

			// Log with attributes
			args := make([]any, len(tt.attrs))
			for i, a := range tt.attrs {
				args[i] = a
			}
			logger.Info("test message", args...)

			// Parse result
			var result map[string]any
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("failed to parse log output: %v", err)
			}

			// Verify expectations
			for k, v := range tt.expected {
				parts := strings.Split(k, ".")
				var val any = result
				var found bool

				// Traverse json map to find key
				for i, part := range parts {
					m, ok := val.(map[string]any)
					if !ok {
						break
					}
					val, ok = m[part]
					if !ok {
						break
					}
					if i == len(parts)-1 {
						found = true
					}
				}

				if !found {
					t.Errorf("key %s not found in output", k)
					continue
				}

				if val != v {
					t.Errorf("key %s: got %v, want %v", k, val, v)
				}
			}
		})
	}
}
