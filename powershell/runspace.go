package powershell

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/smnsjas/go-psrp/wsman"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// PoolClient defines the WSMan operations needed by RunspacePool.
type PoolClient interface {
	Create(ctx context.Context, options map[string]string, creationXML string) (string, error)
	Delete(ctx context.Context, shellID string) error
	Command(ctx context.Context, shellID, commandID, arguments string) (string, error)
	Send(ctx context.Context, shellID, commandID, stream string, data []byte) error
	Receive(ctx context.Context, shellID, commandID string) (*wsman.ReceiveResult, error)
	Signal(ctx context.Context, shellID, commandID, code string) error
	CloseIdleConnections()
}

// Errors for RunspacePool operations.
var (
	ErrPoolNotOpened = errors.New("runspace pool not opened")
	ErrPoolClosed    = errors.New("runspace pool already closed")
)

// WSManBackend manages a PowerShell runspace pool over WSMan.
// It implements the RunspaceBackend interface.
type WSManBackend struct {
	mu sync.RWMutex

	client    PoolClient
	shellID   string
	opened    bool
	closed    bool
	transport *WSManTransport // Reference to the transport for configuration
}

// NewWSManBackend creates a new WSManBackend using the given WSMan client.
func NewWSManBackend(client PoolClient, transport *WSManTransport) *WSManBackend {
	return &WSManBackend{
		client:    client,
		transport: transport,
	}
}

// ShellID returns the WSMan shell ID for this pool.
func (b *WSManBackend) ShellID() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.shellID
}

// Connect implements RunspaceBackend. For WSMan, the transport is already set up.
func (b *WSManBackend) Connect(_ context.Context) error {
	return nil
}

// Transport returns the underlying WSMan transport.
func (b *WSManBackend) Transport() io.ReadWriter {
	return b.transport
}

// Init initializes the WSMan shell and PSRP pool.
func (b *WSManBackend) Init(ctx context.Context, pool *runspace.Pool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrPoolClosed
	}
	if b.opened {
		return nil // Already opened
	}

	// 1. Get Handshake fragments from PSRP pool
	frags, err := pool.GetHandshakeFragments()
	if err != nil {
		return err
	}
	creationXML := base64.StdEncoding.EncodeToString(frags)

	// 2. Create WSMan Shell
	// Add protocolversion option as required by PSRP
	options := map[string]string{
		"protocolversion": "2.3",
	}

	shellID, err := b.client.Create(ctx, options, creationXML)
	if err != nil {
		return err
	}

	b.shellID = shellID
	b.opened = true

	// 3. Open PSRP pool (skip handshake send as we did it in Create)
	pool.SkipHandshakeSend = true
	return pool.Open(ctx)
}

// Close terminates all pipelines and closes the WSMan shell.
func (b *WSManBackend) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.opened {
		return ErrPoolNotOpened
	}
	if b.closed {
		return nil // Already closed
	}

	err := b.client.Delete(ctx, b.shellID)
	if err != nil {
		return err
	}

	b.closed = true
	return nil
}

// PreparePipeline creates the WSMan command and returns a per-pipeline transport.
func (b *WSManBackend) PreparePipeline(ctx context.Context, p *pipeline.Pipeline, payload string) (io.Reader, func(), error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.opened {
		return nil, nil, ErrPoolNotOpened
	}
	if b.closed {
		return nil, nil, ErrPoolClosed
	}

	// 1. Create WSMan Command (Pipeline)
	// We use the ID from the pipeline to ensure proper routing of Receive responses
	pipelineID := strings.ToUpper(p.ID().String())

	returnedID, err := b.client.Command(ctx, b.shellID, pipelineID, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("create wsman command: %w", err)
	}

	// 2. Create a per-pipeline transport for receiving
	// Each pipeline gets its own transport with its specific commandID
	// This allows concurrent pipelines to receive independently
	pipelineTransport := NewWSManTransport(b.client, b.shellID, returnedID)
	pipelineTransport.SetContext(ctx)

	// 3. Setup cleanup function
	cleanup := func() {
		// Terminate the command on WSMan side
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = b.client.Signal(ctx, b.shellID, returnedID, SignalTerminate)
	}

	// 4. Skip PSRP Invoke Send
	// Since we sent the CreatePipeline message in the WSMan Command arguments,
	// we must tell go-psrpcore NOT to send it again over the transport.
	p.SkipInvokeSend()

	return pipelineTransport, cleanup, nil
}
