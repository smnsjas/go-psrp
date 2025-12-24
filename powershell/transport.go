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

	err := t.client.Send(ctx, t.shellID, t.commandID, "stdin", p)
	if err != nil {
		return 0, fmt.Errorf("wsman send: %w", err)
	}
	return len(p), nil
}

// Read receives data from the command's stdout via WSMan Receive.
// Returns io.EOF when the command completes.
func (t *WSManTransport) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

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

	// Poll for more data
	result, err := t.client.Receive(t.ctx, t.shellID, t.commandID)
	if err != nil {
		return 0, fmt.Errorf("wsman receive: %w", err)
	}

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
