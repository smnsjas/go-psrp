package powershell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/smnsjas/go-psrp/wsman"
)

// WSManTransport implements io.ReadWriter over WSMan Send/Receive operations.
// This is the bridge between go-psrpcore (which expects io.ReadWriter) and
// our WSMan client (which provides HTTP-based Send/Receive).
// WSManTransport implements io.ReadWriter over WSMan Send/Receive operations.
// This is the bridge between go-psrpcore (which expects io.ReadWriter) and
// our WSMan client (which provides HTTP-based Send/Receive).
type WSManTransport struct {
	mu      sync.Mutex
	writeMu sync.Mutex // Serializes writes to ensure fragment order

	client    PoolClient
	epr       *wsman.EndpointReference
	commandID string
	ctx       context.Context

	// Buffered data from Receive
	readBuf bytes.Buffer
	done    bool
}

// NewWSManTransport creates a transport that bridges WSMan to io.ReadWriter.
// The client, epr, and commandID can be set later via Configure if needed.
func NewWSManTransport(client PoolClient, epr *wsman.EndpointReference, commandID string) *WSManTransport {
	return &WSManTransport{
		client:    client,
		epr:       epr,
		commandID: commandID,
		ctx:       context.Background(),
	}
}

// SetContext sets the context for operations.
func (t *WSManTransport) SetContext(ctx context.Context) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ctx = ctx
}

// Write sends data to the command's stdin via WSMan Send.
// The data is base64-encoded as required by WSMan Stream elements.
func (t *WSManTransport) Write(p []byte) (int, error) {
	// Serialize writes to ensure fragments arrive at the server in order.
	// PSRP relies on a strict sequence number; out-of-order delivery
	// causes protocol violations.
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.mu.Lock()
	ctx := t.ctx
	t.mu.Unlock()

	if t.client == nil {
		return 0, fmt.Errorf("transport not configured")
	}

	// Send PSRP data to stdin stream
	err := t.client.Send(ctx, t.epr, t.commandID, "stdin", p)
	if err != nil {
		return 0, fmt.Errorf("wsman send: %w", err)
	}
	return len(p), nil
}

// Read receives data from the command's stdout via WSMan Receive.
// Returns io.EOF when the command completes.
// This method blocks until data is available or the context is cancelled.
func (t *WSManTransport) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client == nil {
		return 0, fmt.Errorf("transport not configured")
	}

	// Check context first
	if err := t.ctx.Err(); err != nil {
		return 0, err
	}

	// Return buffered data if available
	if t.readBuf.Len() > 0 {
		return t.readBuf.Read(p)
	}

	// Already done
	if t.done {
		return 0, io.EOF
	}

	// Poll for more data with retry loop
	// WSMan Receive is a long-poll but may return empty on timeout
	for {
		// Check context before each poll
		if err := t.ctx.Err(); err != nil {
			return 0, err
		}

		// Receive output for this command.
		// Note: For concurrent pipelines, the transport must be configured per-pipeline.
		result, err := t.client.Receive(t.ctx, t.epr, t.commandID)
		if err != nil {
			return 0, fmt.Errorf("wsman receive: %w", err)
		}

		// Buffer the stdout (already decoded from base64 by wsman.Client)
		if len(result.Stdout) > 0 {
			t.readBuf.Write(result.Stdout)
		}

		// Mark done if command completed
		if result.Done {
			t.done = true
		}

		// Return buffered data if we got any
		if t.readBuf.Len() > 0 {
			return t.readBuf.Read(p)
		}

		// If done with no more data, return EOF
		if t.done {
			return 0, io.EOF
		}

		// No data yet, WSMan timed out - poll again
		// The WSMan Receive timeout is handled by the server (~60s)
		// so this loop won't spin, it just re-polls after timeout
	}
}

// Close signals the command to terminate.
func (t *WSManTransport) Close() error {
	t.mu.Lock()
	ctx := t.ctx
	t.mu.Unlock()

	return t.client.Signal(ctx, t.epr, t.commandID, SignalTerminate)
}

// Configure sets the WSMan client and IDs for the transport.
// This allows the transport to be created before the shell/command are established.
func (t *WSManTransport) Configure(client PoolClient, epr *wsman.EndpointReference, commandID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client = client
	t.epr = epr
	t.commandID = commandID
}

// CloseIdleConnections closes any idle connections in the underlying WSMan client.
// This forces a fresh NTLM handshake for subsequent requests.
func (t *WSManTransport) CloseIdleConnections() {
	if t.client != nil {
		t.client.CloseIdleConnections()
	}
}
