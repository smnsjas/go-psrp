//go:build windows

package powershell

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrp/hvsock"
	"github.com/smnsjas/go-psrpcore/outofproc"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

var hvDebug = os.Getenv("PSRP_DEBUG") != ""

func hvDebugf(format string, args ...interface{}) {
	if hvDebug {
		log.Printf("[hvsock-backend] "+format, args...)
	}
}

type HvSocketBackend struct {
	mu sync.Mutex

	vmID       uuid.UUID
	domain     string
	username   string
	password   string
	configName string

	conn    net.Conn
	adapter *outofproc.Adapter
	poolID  uuid.UUID

	connected bool
	closed    bool
}

func NewHvSocketBackend(vmID uuid.UUID, domain, username, password, configName string, poolID uuid.UUID) *HvSocketBackend {
	return &HvSocketBackend{
		vmID:       vmID,
		domain:     domain,
		username:   username,
		password:   password,
		configName: configName,
		poolID:     poolID,
	}
}

func (b *HvSocketBackend) Connect(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.connected {
		return nil
	}
	if b.closed {
		return ErrPoolClosed
	}

	hvDebugf("Connecting to VM %s", b.vmID)
	conn, err := hvsock.ConnectAndAuthenticate(ctx, b.vmID, b.domain, b.username, b.password, b.configName)
	if err != nil {
		return fmt.Errorf("hvsock connect: %w", err)
	}

	// Wrap connection with debug logging if PSRP_DEBUG is set
	if hvDebug {
		conn = &debugConn{conn, "wire"}
	}
	b.conn = conn
	hvDebugf("Connection established")

	// Clear deadline for PSRP operations
	_ = conn.SetDeadline(time.Time{})

	// Create OutOfProc Adapter
	hvDebugf("Creating OutOfProc transport and adapter (poolID=%s)", b.poolID)
	transport := outofproc.NewTransportFromReadWriter(conn)
	b.adapter = outofproc.NewAdapter(transport, b.poolID)
	hvDebugf("Adapter created")

	b.connected = true
	return nil
}

func (b *HvSocketBackend) Transport() io.ReadWriter {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.adapter
}

func (b *HvSocketBackend) Init(ctx context.Context, pool *runspace.Pool) error {
	b.mu.Lock()
	if !b.connected {
		b.mu.Unlock()
		return fmt.Errorf("backend not connected")
	}
	b.mu.Unlock()

	hvDebugf("Opening PSRP pool...")
	err := pool.Open(ctx)
	if err != nil {
		hvDebugf("Pool.Open failed: %v", err)
		return err
	}
	hvDebugf("Pool.Open succeeded")
	return nil
}

// ShellID returns the implementation identifier.
func (b *HvSocketBackend) ShellID() string {
	return b.poolID.String()
}

// Reattach connects to an existing runspace pool on the VM.
// shellID is ignored for HvSocket as the connection is defined by VMID/ConfigName.
func (b *HvSocketBackend) Reattach(ctx context.Context, pool *runspace.Pool, _ string) error {
	// For HvSocket, Reattach implies ensuring a specified connection to the VM is working.
	// If the client logic decided to reconnect, it implies the previous connection is broken.
	// We proactively reset the connection to ensure we get a fresh socket.
	b.mu.Lock()
	if b.connected {
		hvDebugf("[reattach] Resetting existing connection to force fresh socket")
		if b.conn != nil {
			_ = b.conn.Close()
		}
		b.connected = false
		b.adapter = nil // Adapter will be recreated in Connect
	}
	b.mu.Unlock()

	// 1. Establish socket connection if needed
	if err := b.Connect(ctx); err != nil {
		return fmt.Errorf("connect socket: %w", err)
	}

	// Update the pool's transport to use the new adapter!
	// This is critical because the pool was likely created with a nil or stale adapter
	// in Client.Reconnect.
	pool.SetTransport(b.adapter)

	// 2. Perform PSRP handshake
	// For HvSocket, the server-side session is typically destroyed when the connection breaks
	// (e.g., VM pause). We need to create a NEW session using Open(), not reconnect to an
	// existing one using Connect(). Connect() sends CONNECT_RUNSPACEPOOL which the server
	// won't recognize if the old session is gone.
	hvDebugf("Performing PSRP session establishment (Open)...")
	if err := pool.Open(ctx); err != nil {
		return fmt.Errorf("pool open: %w", err)
	}
	hvDebugf("PSRP session established successfully")

	return nil
}

func (b *HvSocketBackend) PreparePipeline(ctx context.Context, p *pipeline.Pipeline, payload string) (io.Reader, func(), error) {
	// For HvSocket (OutOfProc), we don't need a separate transport per pipeline.
	// The shared adapter handles all pipelines. Return nil for the transport.
	return nil, func() {}, nil
}

// SupportsPSRPKeepalive returns true for HvSocket.
// HvSocket uses OUT-OF-PROC transport which supports PSRP-level keepalive messages.
func (b *HvSocketBackend) SupportsPSRPKeepalive() bool {
	return true
}

func (b *HvSocketBackend) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true

	hvDebugf("=== Starting backend close sequence ===")

	// Step 1: Close the adapter (sends protocol-level Close)
	if b.adapter != nil {
		hvDebugf("Step 1: Closing adapter...")
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		done := make(chan struct{})
		go func() {
			b.adapter.Close()
			close(done)
		}()

		select {
		case <-done:
			hvDebugf("Adapter closed successfully")
		case <-closeCtx.Done():
			hvDebugf("Adapter close timed out")
		}
	}

	// Step 2: Close the socket connection
	if b.conn != nil {
		hvDebugf("Step 2: Closing socket...")

		// Set deadline to prevent hanging
		b.conn.SetDeadline(time.Now().Add(2 * time.Second))

		if err := b.conn.Close(); err != nil {
			hvDebugf("Socket close error (expected): %v", err)
		}
	}

	// Step 3: Wait for guest to clean up
	// The vmicvmsession service needs time to:
	// - Terminate the PowerShell process
	// - Release the HvSocket endpoint binding
	// - Clean up internal state
	hvDebugf("Step 3: Waiting for guest cleanup (1.5s)...")
	time.Sleep(1500 * time.Millisecond)

	hvDebugf("=== Backend close sequence complete ===")
	return nil
}

// debugConn wraps a net.Conn with read/write logging
type debugConn struct {
	net.Conn
	prefix string
}

func (c *debugConn) Read(p []byte) (n int, err error) {
	hvDebugf("[%s] READ waiting...", c.prefix)
	n, err = c.Conn.Read(p)
	if n > 0 {
		data := p[:n]
		if len(data) > 200 {
			hvDebugf("[%s] READ %d bytes: %s... (truncated)", c.prefix, n, string(data[:200]))
		} else {
			hvDebugf("[%s] READ %d bytes: %s", c.prefix, n, string(data))
		}
	}
	if err != nil {
		msg := err.Error()
		// Filter out expected errors during close
		if err == io.EOF ||
			msg == "nop" ||
			strings.Contains(msg, "closed network connection") ||
			strings.Contains(msg, "connection was aborted") ||
			strings.Contains(msg, "connection reset") {
			hvDebugf("[%s] READ closed (expected)", c.prefix)
		} else {
			hvDebugf("[%s] READ error: %v", c.prefix, err)
		}
	}
	return n, err
}

func (c *debugConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if n > 0 {
		data := p[:n]
		if len(data) > 200 {
			hvDebugf("[%s] WRITE %d bytes: %s... (truncated)", c.prefix, n, string(data[:200]))
		} else {
			hvDebugf("[%s] WRITE %d bytes: %s", c.prefix, n, string(data))
		}
	}
	if err != nil {
		hvDebugf("[%s] WRITE error: %v", c.prefix, err)
	}
	return n, err
}
