package client

import (
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/runspace"
)

func TestClient_State(t *testing.T) {
	// 1. Initial State (No Pool)
	c := &Client{}
	if got := c.State(); got != runspace.StateBeforeOpen {
		t.Errorf("State() = %v, want %v", got, runspace.StateBeforeOpen)
	}

	// 2. Mock Pool State
	// We can't easily mock runspace.Pool state directly as fields are private
	// But we can check if it delegates by initializing a real pool
	transport := &struct{ io.ReadWriter }{} // Dummy
	pool := runspace.New(transport, uuid.New())
	c.psrpPool = pool
	if got := c.State(); got != runspace.StateBeforeOpen {
		t.Errorf("State() = %v, want %v", got, runspace.StateBeforeOpen)
	}

	// We can't transition mock pool easily without full handshake simulation
	// covered in integration tests
}

func TestClient_Health(t *testing.T) {
	// 1. Initial State (Unknown)
	c := &Client{}
	if got := c.Health(); got != HealthUnknown {
		t.Errorf("Health() = %v, want %v", got, HealthUnknown)
	}

	// 2. Prepared State (Unknown)
	transport := &spyTransport{writes: make(chan []byte, 10)}
	pool := runspace.New(transport, uuid.New())
	c.psrpPool = pool
	if got := c.Health(); got != HealthUnknown {
		t.Errorf("Health() = %v, want %v", got, HealthUnknown)
	}

	// 3. Forced Opened State (Degraded because available=0)
	// We use the SkipHandshakeSend trick
	c.psrpPool.SkipHandshakeSend = true
	// We must supply a proper context and transport because Connect calls StartDispatchLoop
	// which launches a goroutine reading from transport.
	// Our spyTransport blocks Read, which is fine.
	err := c.psrpPool.Connect(context.Background())
	if err != nil {
		t.Fatalf("psrpPool.Connect() error = %v", err)
	}

	if got := c.State(); got != runspace.StateOpened {
		t.Errorf("State() = %v, want %v", got, runspace.StateOpened)
	}
	// Default available runspaces is 0
	if got := c.Health(); got != HealthDegraded {
		t.Errorf("Health() = %v, want %v", got, HealthDegraded)
	}

	// Note: To test 'Healthy', we would need to mock the server sending a RUNSPACE_AVAILABILITY message.
	// That ends up being a functional test of runspace.Pool, not just Client.Health logic.
	// Since we verified the switch case lands on Degraded (Opened + 0), we trust the if statement logic.

	// 4. Broken (Unhealthy)
	// We can't force Broken state easily on private pool.
	// But we can simulate close.
	_ = c.psrpPool.Close(context.Background())
	// Close() transitions to Closing then Closed.
	// Wait a bit?
	// Close() is async?
	// runspace.Close sends message and waits. Our spy transport blocks write?
	// SendMessage might fail or block in test.
}
