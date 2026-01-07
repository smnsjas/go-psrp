package client

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/runspace"
)

func TestClient_CloseWithStrategy_Force(t *testing.T) {
	mockBackend := &MockBackend{
		CloseFunc: func(ctx context.Context) error {
			return errors.New("should not be called in Force mode")
		},
	}

	c := &Client{
		config:    DefaultConfig(),
		backend:   mockBackend,
		connected: true,
		closed:    false,
		psrpPool:  runspace.New(&noOpTransport{}, uuid.New()),
	}

	// Force close should not call backend.Close
	if err := c.CloseWithStrategy(context.Background(), CloseStrategyForce); err != nil {
		t.Fatalf("CloseWithStrategy(Force) failed: %v", err)
	}

	if !c.closed {
		t.Error("Client should be marked closed")
	}
}

func TestClient_CloseWithStrategy_Graceful(t *testing.T) {
	backendClosed := false
	mockBackend := &MockBackend{
		CloseFunc: func(ctx context.Context) error {
			backendClosed = true
			return nil
		},
	}

	c := &Client{
		config:    DefaultConfig(),
		backend:   mockBackend,
		connected: true,
		closed:    false,
		psrpPool:  runspace.New(&noOpTransport{}, uuid.New()),
	}

	// Graceful close should call backend.Close
	if err := c.CloseWithStrategy(context.Background(), CloseStrategyGraceful); err != nil {
		t.Fatalf("CloseWithStrategy(Graceful) failed: %v", err)
	}

	if !c.closed {
		t.Error("Client should be marked closed")
	}
	if !backendClosed {
		t.Error("Backend.Close() was not called in Graceful mode")
	}
}

func TestClient_Reconnect_Mock(t *testing.T) {
	reattachCalled := false
	expectedShellID := "test-shell-id"

	mockBackend := &MockBackend{
		ReattachFunc: func(ctx context.Context, pool *runspace.Pool, shellID string) error {
			reattachCalled = true
			if shellID != expectedShellID {
				t.Errorf("Expected shellID %s, got %s", expectedShellID, shellID)
			}
			return nil
		},
		TransportFunc: func() io.ReadWriter { return &noOpTransport{} },
	}
	// Need to fix TransportFunc signature in mock_test.go?
	// mock_test.go defines TransportFunc func() io.ReadWriter
	// So here needs to match.

	c := &Client{
		config:    DefaultConfig(),
		backend:   mockBackend,
		connected: false, // Disconnected initially
		closed:    false,
		callID:    newCallIDManager(),
		// psrpPool is nil initially as well usually
	}

	if err := c.Reconnect(context.Background(), expectedShellID); err != nil {
		t.Fatalf("Reconnect failed: %v", err)
	}

	if !reattachCalled {
		t.Error("Backend.Reattach() was not called")
	}
	if !c.connected {
		t.Error("Client should be marked connected")
	}
	if c.psrpPool == nil {
		t.Error("Client.psrpPool should be initialized")
	}
	if c.callID.Current() != 2 {
		t.Errorf("Expected callID synced to 2, got %d", c.callID.Current())
	}
}
