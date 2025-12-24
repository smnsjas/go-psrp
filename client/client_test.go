package client

import (
	"context"
	"testing"
	"time"
)

const (
	testUsername = "testuser"
	testPassword = "testpass"
)

// TestConfig_Defaults verifies default configuration values.
func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != 5985 {
		t.Errorf("Port = %d, want 5985", cfg.Port)
	}
	if cfg.UseTLS {
		t.Error("UseTLS should be false by default")
	}
	if cfg.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want 60s", cfg.Timeout)
	}
}

// TestConfig_HTTPS verifies HTTPS configuration.
func TestConfig_HTTPS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UseTLS = true

	if cfg.Port != 5985 {
		// Port doesn't auto-change, user sets explicitly
		t.Errorf("Port = %d, want 5985", cfg.Port)
	}
}

// TestConfig_Validate verifies configuration validation.
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "valid basic auth",
			cfg:     Config{Username: "user", Password: "pass"},
			wantErr: false,
		},
		{
			name:    "missing username",
			cfg:     Config{Password: "pass"},
			wantErr: true,
		},
		{
			name:    "missing password",
			cfg:     Config{Username: "user"},
			wantErr: true,
		},
		{
			name:    "empty config",
			cfg:     Config{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewClient_Basic verifies basic client creation.
func TestNewClient_Basic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Username = testUsername
	cfg.Password = testPassword

	client, err := New("testserver", cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if client == nil {
		t.Error("client is nil")
	}

	if client.Endpoint() != "http://testserver:5985/wsman" {
		t.Errorf("Endpoint = %q, want http://testserver:5985/wsman", client.Endpoint())
	}
}

// TestNewClient_HTTPS verifies HTTPS client creation.
func TestNewClient_HTTPS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Username = testUsername
	cfg.Password = testPassword
	cfg.UseTLS = true
	cfg.Port = 5986

	client, err := New("testserver", cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if client.Endpoint() != "https://testserver:5986/wsman" {
		t.Errorf("Endpoint = %q, want https://testserver:5986/wsman", client.Endpoint())
	}
}

// TestClient_Close verifies client close is idempotent.
func TestClient_Close(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Username = testUsername
	cfg.Password = testPassword

	client, _ := New("testserver", cfg)

	// Close should not panic even without connection
	err := client.Close(context.Background())
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Second close should also succeed
	err = client.Close(context.Background())
	if err != nil {
		t.Errorf("Second Close failed: %v", err)
	}
}
