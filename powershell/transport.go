package powershell

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"github.com/smnsjas/go-psrp/wsman"
)

// WSManTransport implements io.ReadWriter over WSMan Send/Receive operations.
// This is the bridge between go-psrpcore (which expects io.ReadWriter) and
// our WSMan client (which provides HTTP-based Send/Receive).
type WSManTransport struct {
	mu sync.Mutex

	client    *wsman.Client
	shellID   string
	commandID string
	ctx       context.Context

	// Buffered data from Receive
	readBuf bytes.Buffer
	done    bool
}

// NewWSManTransport creates a transport that bridges WSMan to io.ReadWriter.
// The client, shellID, and commandID can be set later via Configure if needed.
func NewWSManTransport(client *wsman.Client, shellID, commandID string) *WSManTransport {
	return &WSManTransport{
		client:    client,
		shellID:   shellID,
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
	t.mu.Lock()
	ctx := t.ctx
	t.mu.Unlock()

	if t.client == nil {
		return 0, fmt.Errorf("transport not configured")
	}

	fmt.Printf("DEBUG: transport.Write called, %d bytes\n", len(p))

	// Send PSRP data to stdin stream
	err := t.client.Send(ctx, t.shellID, t.commandID, "stdin", p)
	if err != nil {
		fmt.Printf("DEBUG: transport.Write failed: %v\n", err)
		return 0, fmt.Errorf("wsman send: %w", err)
	}
	fmt.Printf("DEBUG: transport.Write succeeded\n")
	return len(p), nil
}

// Read receives data from the command's stdout via WSMan Receive.
// Returns io.EOF when the command completes.
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

	fmt.Printf("DEBUG: transport.Read calling Receive...\n")

	// Poll for more data
	result, err := t.client.Receive(t.ctx, t.shellID, t.commandID)
	if err != nil {
		fmt.Printf("DEBUG: transport.Read failed: %v\n", err)
		return 0, fmt.Errorf("wsman receive: %w", err)
	}

	fmt.Printf("DEBUG: transport.Read got response, Stdout=%d bytes, Done=%v\n", len(result.Stdout), result.Done)

	// Decode and buffer the stdout (it comes as base64 from WSMan)
	if len(result.Stdout) > 0 {
		decoded, err := base64.StdEncoding.DecodeString(string(result.Stdout))
		if err != nil {
			// If not base64, use raw bytes
			t.readBuf.Write(result.Stdout)
		} else {
			t.readBuf.Write(decoded)
		}
	}

	// Mark done if command completed
	if result.Done {
		t.done = true
	}

	// Return buffered data or EOF
	if t.readBuf.Len() > 0 {
		return t.readBuf.Read(p)
	}

	if t.done {
		return 0, io.EOF
	}

	// No data yet, return 0 (caller should retry)
	return 0, nil
}

// Close signals the command to terminate.
func (t *WSManTransport) Close() error {
	t.mu.Lock()
	ctx := t.ctx
	t.mu.Unlock()

	return t.client.Signal(ctx, t.shellID, t.commandID, SignalTerminate)
}

// Configure sets the WSMan client and IDs for the transport.
// This allows the transport to be created before the shell/command are established.
func (t *WSManTransport) Configure(client *wsman.Client, shellID, commandID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client = client
	t.shellID = shellID
	t.commandID = commandID
}

// CloseIdleConnections closes any idle connections in the underlying WSMan client.
// This forces a fresh NTLM handshake for subsequent requests.
func (t *WSManTransport) CloseIdleConnections() {
	if t.client != nil {
		t.client.CloseIdleConnections()
	}
}
