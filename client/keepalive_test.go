package client

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/smnsjas/go-psrp/powershell"
	"github.com/smnsjas/go-psrpcore/runspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type spyTransport struct {
	writes chan []byte
}

func (t *spyTransport) Read(p []byte) (n int, err error) {
	// Block forever or return EOF?
	// For keepalive, we just need to keep the connection 'open'.
	// Blocking is safer to simulate an idle connection.
	select {}
}

func (t *spyTransport) Write(p []byte) (n int, err error) {
	// Make a copy
	data := make([]byte, len(p))
	copy(data, p)

	// Send to channel non-blocking
	select {
	case t.writes <- data:
	default:
	}
	return len(p), nil
}

func TestClient_Keepalive(t *testing.T) {
	// Setup spy transport
	transport := &spyTransport{
		writes: make(chan []byte, 10),
	}

	// Setup mock backend
	backend := &MockBackend{
		TransportFunc: func() io.ReadWriter {
			return transport
		},
		InitFunc: func(ctx context.Context, pool *runspace.Pool) error {
			// Init is called in Connect.
			// It returns nil, meaning successful backend init.
			// The pool is already created by client.
			return nil
		},
		SupportsPSRPKeepaliveFunc: func() bool {
			return true
		},
	}

	cfg := Config{
		KeepAliveInterval: 50 * time.Millisecond,
		AuthType:          AuthBasic,
		Username:          "user",
		Password:          "pass",
	}

	c, err := New("host", cfg)
	require.NoError(t, err)

	// Inject mock backend via factory
	c.backendFactory = func() (powershell.RunspaceBackend, error) {
		return backend, nil
	}

	// We can manually start keepalive to avoid full Connect flow overhead/mocking
	// Since we are inside `package client`, we can hack `c.psrpPool`?
	// But `c.psrpPool` is created in `Connect`.
	// If we skip `Connect`, `c.psrpPool` is nil, and keepalive loop aborts.

	// So we MUST call `Connect`.
	// Connect calls backend.Connect(), backend.Transport(), then runspace.New(), then pool.Connect()
	// runspace.Pool.Connect() sends handshake messages.
	// Our spyTransport ignores reads (blocks).
	// runspace.Pool.Connect() expects responses! It will timeout.

	// So `c.Connect()` will fail or block.

	// APPROACH B: Manually set up the client state for keepalive.
	c.mu.Lock()
	// Mock the pool
	// We use runspace.New() which creates a real pool with our spy transport.
	c.psrpPool = runspace.New(transport, c.poolID)

	// CRITICAL: We must transition pool to StateOpened so SendGetAvailableRunspaces works.
	// We use SkipHandshakeSend = true to bypass network handshake and force state transition.
	c.psrpPool.SkipHandshakeSend = true
	if err := c.psrpPool.Connect(context.Background()); err != nil {
		c.mu.Unlock()
		t.Fatalf("Fake connect failed: %v", err)
	}

	// We need to set backend too for startKeepalive check (if any?)
	c.backend = backend
	c.connected = true
	// Start keepalive directly
	c.startKeepaliveLocked()
	c.mu.Unlock()

	// Validate
	select {
	case data := <-transport.writes:
		// We received something!
		assert.NotEmpty(t, data)
		// PSRP sends fragments, not raw messages.
		// Fragment header is 21 bytes (8+8+1+4).
		// We just verify we received a valid-looking chunk of data.
		assert.GreaterOrEqual(t, len(data), 21, "Should receive at least a fragment header")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for keepalive message")
	}

	c.stopKeepaliveAndWait()
}
