// Package powershell provides the bridge between WSMan transport and go-psrpcore.
package powershell

import (
	"bytes"
	"context"
	"io"
	"sync"

	"github.com/smnsjas/go-psrp/wsman"
)

// WSManClient defines the WSMan operations needed by the adapter.
type WSManClient interface {
	Send(ctx context.Context, shellID, commandID, stream string, data []byte) error
	Receive(ctx context.Context, shellID, commandID string) (*wsman.ReceiveResult, error)
}

// Adapter bridges WSMan's request/response model to go-psrpcore's io.ReadWriter interface.
// It handles the conversion between WSMan Send/Receive and streaming I/O.
type Adapter struct {
	mu sync.Mutex

	client    WSManClient
	shellID   string
	commandID string

	// Read buffering
	readBuf bytes.Buffer
	done    bool

	// Context for cancellation
	ctx context.Context
}

// NewAdapter creates a new adapter for the given WSMan client and command.
func NewAdapter(client WSManClient, shellID, commandID string) *Adapter {
	return &Adapter{
		client:    client,
		shellID:   shellID,
		commandID: commandID,
		ctx:       context.Background(),
	}
}

// SetContext sets the context for cancellation of operations.
func (a *Adapter) SetContext(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ctx = ctx
}

// Write sends data to the command's stdin stream via WSMan Send.
// Implements io.Writer.
func (a *Adapter) Write(p []byte) (int, error) {
	a.mu.Lock()
	ctx := a.ctx
	a.mu.Unlock()

	err := a.client.Send(ctx, a.shellID, a.commandID, "stdin", p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read receives data from the command's stdout stream via WSMan Receive.
// Implements io.Reader.
//
// The adapter buffers received data and returns it in chunks as requested.
// If no data is immediately available, it polls the WSMan Receive operation.
// Returns io.EOF when the command has completed and all data has been read.
func (a *Adapter) Read(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check context first
	if err := a.ctx.Err(); err != nil {
		return 0, err
	}

	// Return buffered data if available
	if a.readBuf.Len() > 0 {
		return a.readBuf.Read(p)
	}

	// Check if already done
	if a.done {
		return 0, io.EOF
	}

	// Poll for more data
	result, err := a.client.Receive(a.ctx, a.shellID, a.commandID)
	if err != nil {
		return 0, err
	}

	// Buffer the received data
	if len(result.Stdout) > 0 {
		a.readBuf.Write(result.Stdout)
	}

	// Mark done if command completed
	if result.Done {
		a.done = true
	}

	// Return buffered data or EOF
	if a.readBuf.Len() > 0 {
		return a.readBuf.Read(p)
	}

	if a.done {
		return 0, io.EOF
	}

	// No data available yet but not done - return 0 bytes
	// The caller should retry
	return 0, nil
}
