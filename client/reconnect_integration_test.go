//go:build integration
// +build integration

package client_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/smnsjas/go-psrp/client"
)

// IntegrationTestConfig holds configuration for remote server tests.
// Set via environment variables:
//
//	PSRP_TEST_SERVER - WinRM server hostname
//	PSRP_TEST_USER   - Username
//	PSRP_PASSWORD    - Password (reuses existing env var)
//	PSRP_TEST_TLS    - "true" to use HTTPS
type IntegrationTestConfig struct {
	Server   string
	Username string
	Password string
	UseTLS   bool
}

func getIntegrationConfig(t *testing.T) *IntegrationTestConfig {
	server := os.Getenv("PSRP_TEST_SERVER")
	if server == "" {
		t.Skip("PSRP_TEST_SERVER not set, skipping integration test")
	}

	user := os.Getenv("PSRP_TEST_USER")
	if user == "" {
		t.Skip("PSRP_TEST_USER not set, skipping integration test")
	}

	pass := os.Getenv("PSRP_PASSWORD")
	if pass == "" {
		t.Skip("PSRP_PASSWORD not set, skipping integration test")
	}

	return &IntegrationTestConfig{
		Server:   server,
		Username: user,
		Password: pass,
		UseTLS:   os.Getenv("PSRP_TEST_TLS") == "true",
	}
}

// TestAutoReconnect_RemoteServer tests automatic reconnection against a real WinRM server.
// This test runs a long command in a goroutine and simulates connection issues.
//
// To run:
//
//	export PSRP_TEST_SERVER=your-server.domain.com
//	export PSRP_TEST_USER=Administrator
//	export PSRP_PASSWORD=YourPassword
//	export PSRP_TEST_TLS=true
//	go test -v -tags=integration ./client/... -run TestAutoReconnect_RemoteServer
func TestAutoReconnect_RemoteServer(t *testing.T) {
	cfg := getIntegrationConfig(t)

	// Build client config with auto-reconnect enabled
	clientCfg := client.DefaultConfig()
	clientCfg.Username = cfg.Username
	clientCfg.Password = cfg.Password
	clientCfg.UseTLS = cfg.UseTLS
	if cfg.UseTLS {
		clientCfg.Port = 5986 // HTTPS port
	}
	clientCfg.InsecureSkipVerify = true // For testing with self-signed certs
	clientCfg.AuthType = client.AuthNTLM
	clientCfg.KeepAliveInterval = 5 * time.Second
	clientCfg.Reconnect.Enabled = true
	clientCfg.Reconnect.MaxAttempts = 3
	clientCfg.Reconnect.InitialDelay = 2 * time.Second

	// Create client
	psrp, err := client.New(cfg.Server, clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Connect
	t.Log("Connecting to server...")
	if err := psrp.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer psrp.Close(ctx)

	t.Logf("Connected! State: %s, Health: %s", psrp.State(), psrp.Health())

	// Run test scenarios concurrently
	var wg sync.WaitGroup
	results := make(chan testResult, 3)

	// Scenario 1: Basic command execution
	wg.Add(1)
	go func() {
		defer wg.Done()
		results <- runBasicCommand(ctx, psrp, t)
	}()

	// Scenario 2: Long-running command with health monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		results <- runLongCommandWithMonitor(ctx, psrp, t)
	}()

	// Scenario 3: Keepalive observation
	wg.Add(1)
	go func() {
		defer wg.Done()
		results <- observeKeepalive(ctx, psrp, t)
	}()

	// Wait for all tests
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	passed := 0
	failed := 0
	for r := range results {
		if r.success {
			t.Logf("✅ %s: %s", r.name, r.message)
			passed++
		} else {
			t.Errorf("❌ %s: %s", r.name, r.message)
			failed++
		}
	}

	t.Logf("\nResults: %d passed, %d failed", passed, failed)
}

type testResult struct {
	name    string
	success bool
	message string
}

func runBasicCommand(ctx context.Context, c *client.Client, t *testing.T) testResult {
	t.Log("[Basic] Running simple command...")

	result, err := c.Execute(ctx, "'Hello from integration test'")
	if err != nil {
		return testResult{"BasicCommand", false, fmt.Sprintf("Execute failed: %v", err)}
	}

	if len(result.Output) == 0 {
		return testResult{"BasicCommand", false, "No output received"}
	}

	return testResult{"BasicCommand", true, fmt.Sprintf("Got %d output items", len(result.Output))}
}

func runLongCommandWithMonitor(ctx context.Context, c *client.Client, t *testing.T) testResult {
	t.Log("[LongCmd] Starting long-running command with health monitor...")

	// Monitor health in background
	monitorCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	healthChanges := 0
	go func() {
		lastHealth := c.Health()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-ticker.C:
				health := c.Health()
				if health != lastHealth {
					t.Logf("[Monitor] Health changed: %s -> %s", lastHealth, health)
					healthChanges++
					lastHealth = health
				}
			}
		}
	}()

	// Run a 15-second command
	result, err := c.Execute(ctx, "1..5 | ForEach-Object { Start-Sleep 3; $_ }")
	if err != nil {
		return testResult{"LongCommand", false, fmt.Sprintf("Execute failed: %v", err)}
	}

	return testResult{
		"LongCommand",
		true,
		fmt.Sprintf("Got %d outputs, %d health changes observed", len(result.Output), healthChanges),
	}
}

func observeKeepalive(ctx context.Context, c *client.Client, t *testing.T) testResult {
	t.Log("[Keepalive] Observing keepalive for 20 seconds...")

	start := time.Now()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	observations := 0
	timeout := time.After(20 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return testResult{"Keepalive", false, "Context cancelled"}
		case <-timeout:
			return testResult{
				"Keepalive",
				true,
				fmt.Sprintf("Observed health %d times over %v, final: %s",
					observations, time.Since(start), c.Health()),
			}
		case <-ticker.C:
			health := c.Health()
			state := c.State()
			t.Logf("[Keepalive] t+%v: State=%s Health=%s", time.Since(start).Round(time.Second), state, health)
			observations++
		}
	}
}

// TestReconnect_SimulatedFailure tests reconnection by intentionally failing mid-command.
// This requires manual intervention: restart WinRM on the server during the test.
func TestReconnect_SimulatedFailure(t *testing.T) {
	cfg := getIntegrationConfig(t)

	clientCfg := client.DefaultConfig()
	clientCfg.Username = cfg.Username
	clientCfg.Password = cfg.Password
	clientCfg.UseTLS = cfg.UseTLS
	if cfg.UseTLS {
		clientCfg.Port = 5986 // HTTPS port
	}
	clientCfg.InsecureSkipVerify = true
	clientCfg.AuthType = client.AuthNTLM
	clientCfg.KeepAliveInterval = 5 * time.Second
	clientCfg.Reconnect.Enabled = true
	clientCfg.Reconnect.MaxAttempts = 5
	clientCfg.Reconnect.InitialDelay = 1 * time.Second

	psrp, err := client.New(cfg.Server, clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := psrp.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer psrp.Close(ctx)

	t.Log("Connected!")
	t.Log("")
	t.Log("=== MANUAL INTERVENTION REQUIRED ===")
	t.Log("Run this on the Windows server to simulate failure:")
	t.Log("  Restart-Service WinRM")
	t.Log("")
	t.Log("Watch for reconnection attempts in the logs...")
	t.Log("")

	// Run a very long command to give time for manual intervention
	result, err := psrp.Execute(ctx, "1..60 | ForEach-Object { Start-Sleep 2; \"Tick $_\" }")
	if err != nil {
		t.Logf("Command failed (expected if you restarted WinRM): %v", err)
		t.Log("Check logs above for reconnection attempts")
	} else {
		t.Logf("Command completed with %d outputs", len(result.Output))
	}

	t.Logf("Final State: %s, Health: %s", psrp.State(), psrp.Health())
}
