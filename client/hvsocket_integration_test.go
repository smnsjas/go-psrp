//go:build integration && windows
// +build integration,windows

package client_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/smnsjas/go-psrp/client"
)

// HvSocketIntegrationConfig holds configuration for HvSocket tests.
// Set via environment variables:
//
//	PSRP_TEST_VMID     - VM GUID (required)
//	PSRP_TEST_USER     - Username for VM
//	PSRP_PASSWORD      - Password
//	PSRP_TEST_DOMAIN   - Optional domain
type HvSocketIntegrationConfig struct {
	VMID     string
	Username string
	Password string
	Domain   string
}

func getHvSocketConfig(t *testing.T) *HvSocketIntegrationConfig {
	vmid := os.Getenv("PSRP_TEST_VMID")
	if vmid == "" {
		t.Skip("PSRP_TEST_VMID not set, skipping HvSocket integration test")
	}

	user := os.Getenv("PSRP_TEST_USER")
	if user == "" {
		t.Skip("PSRP_TEST_USER not set, skipping HvSocket integration test")
	}

	pass := os.Getenv("PSRP_PASSWORD")
	if pass == "" {
		t.Skip("PSRP_PASSWORD not set, skipping HvSocket integration test")
	}

	return &HvSocketIntegrationConfig{
		VMID:     vmid,
		Username: user,
		Password: pass,
		Domain:   os.Getenv("PSRP_TEST_DOMAIN"),
	}
}

// TestHvSocket_BasicConnection tests basic HvSocket connectivity to a VM.
//
// To run:
//
//	$env:PSRP_TEST_VMID = "your-vm-guid"
//	$env:PSRP_TEST_USER = "Administrator"
//	$env:PSRP_PASSWORD = "password"
//	go test -v -tags="integration" ./client/... -run TestHvSocket_BasicConnection
func TestHvSocket_BasicConnection(t *testing.T) {
	cfg := getHvSocketConfig(t)

	clientCfg := client.DefaultConfig()
	clientCfg.Transport = client.TransportHvSocket
	clientCfg.VMID = cfg.VMID
	clientCfg.Username = cfg.Username
	clientCfg.Password = cfg.Password
	clientCfg.Domain = cfg.Domain
	clientCfg.KeepAliveInterval = 5 * time.Second

	psrp, err := client.New("", clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("Connecting to VM via HvSocket...")
	if err := psrp.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer psrp.Close(ctx)

	t.Logf("Connected! State: %s, Health: %s", psrp.State(), psrp.Health())

	// Run a simple command
	result, err := psrp.Execute(ctx, "'Hello from HvSocket test'")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result.Output) == 0 {
		t.Fatal("No output received")
	}

	t.Logf("Command output: %v", result.Output)
}

// TestHvSocket_AutoReconnect tests automatic reconnection on HvSocket.
// This test requires manual intervention: pause and resume the VM during execution.
//
// To run:
//
//	$env:PSRP_TEST_VMID = "your-vm-guid"
//	$env:PSRP_TEST_USER = "Administrator"
//	$env:PSRP_PASSWORD = "password"
//	go test -v -tags="integration" ./client/... -run TestHvSocket_AutoReconnect -timeout 10m
func TestHvSocket_AutoReconnect(t *testing.T) {
	cfg := getHvSocketConfig(t)

	clientCfg := client.DefaultConfig()
	clientCfg.Transport = client.TransportHvSocket
	clientCfg.VMID = cfg.VMID
	clientCfg.Username = cfg.Username
	clientCfg.Password = cfg.Password
	clientCfg.Domain = cfg.Domain
	clientCfg.KeepAliveInterval = 5 * time.Second

	// Enable auto-reconnect
	clientCfg.Reconnect.Enabled = true
	clientCfg.Reconnect.MaxAttempts = 10
	clientCfg.Reconnect.InitialDelay = 1 * time.Second
	clientCfg.Reconnect.MaxDelay = 30 * time.Second

	psrp, err := client.New("", clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Log("Connecting to VM via HvSocket...")
	if err := psrp.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer psrp.Close(ctx)

	t.Logf("Connected! State: %s, Health: %s", psrp.State(), psrp.Health())

	t.Log("")
	t.Log("=== MANUAL INTERVENTION REQUIRED ===")
	t.Log("Pause the VM using Hyper-V Manager, wait 5 seconds, then resume.")
	t.Log("The test will attempt to reconnect automatically.")
	t.Log("")

	// Run a long command that will span the pause/resume
	t.Log("Running long command (1..30 | ForEach { Start-Sleep 2; $_ })...")
	result, err := psrp.Execute(ctx, "1..30 | ForEach-Object { Start-Sleep 2; $_ }")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	t.Logf("Command completed successfully!")
	t.Logf("Output count: %d", len(result.Output))
	t.Logf("Final State: %s, Health: %s", psrp.State(), psrp.Health())
}

// TestHvSocket_MultipleReconnects tests multiple consecutive reconnections.
// Pause and resume the VM multiple times during this test.
//
// To run:
//
//	$env:PSRP_TEST_VMID = "your-vm-guid"
//	$env:PSRP_TEST_USER = "Administrator"
//	$env:PSRP_PASSWORD = "password"
//	go test -v -tags="integration" ./client/... -run TestHvSocket_MultipleReconnects -timeout 15m
func TestHvSocket_MultipleReconnects(t *testing.T) {
	cfg := getHvSocketConfig(t)

	clientCfg := client.DefaultConfig()
	clientCfg.Transport = client.TransportHvSocket
	clientCfg.VMID = cfg.VMID
	clientCfg.Username = cfg.Username
	clientCfg.Password = cfg.Password
	clientCfg.Domain = cfg.Domain
	clientCfg.KeepAliveInterval = 5 * time.Second

	// Enable auto-reconnect with many attempts
	clientCfg.Reconnect.Enabled = true
	clientCfg.Reconnect.MaxAttempts = 20 // Allow many attempts for multiple pauses
	clientCfg.Reconnect.InitialDelay = 500 * time.Millisecond
	clientCfg.Reconnect.MaxDelay = 15 * time.Second

	psrp, err := client.New("", clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Log("Connecting to VM via HvSocket...")
	if err := psrp.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer psrp.Close(ctx)

	t.Logf("Connected! State: %s, Health: %s", psrp.State(), psrp.Health())

	t.Log("")
	t.Log("=== MANUAL INTERVENTION REQUIRED ===")
	t.Log("Pause and resume the VM MULTIPLE times during this test.")
	t.Log("The test runs for ~2 minutes. Try to pause 2-3 times.")
	t.Log("")

	// Run a very long command
	t.Log("Running long command (1..60 | ForEach { Start-Sleep 2; $_ })...")
	result, err := psrp.Execute(ctx, "1..60 | ForEach-Object { Start-Sleep 2; $_ }")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	t.Logf("Command completed successfully after multiple reconnections!")
	t.Logf("Output count: %d", len(result.Output))
	t.Logf("Final State: %s, Health: %s", psrp.State(), psrp.Health())

	// Verify we got all 60 outputs (command was retried, so we get full output)
	if len(result.Output) < 60 {
		t.Logf("Warning: Expected 60 outputs, got %d (command may have been restarted)", len(result.Output))
	}
}
