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
	Create(ctx context.Context, options map[string]string, creationXML string) (*wsman.EndpointReference, error)
	Delete(ctx context.Context, epr *wsman.EndpointReference) error
	Command(ctx context.Context, epr *wsman.EndpointReference, commandID, arguments string) (string, error)
	Send(ctx context.Context, epr *wsman.EndpointReference, commandID, stream string, data []byte) error
	Receive(ctx context.Context, epr *wsman.EndpointReference, commandID string) (*wsman.ReceiveResult, error)
	Signal(ctx context.Context, epr *wsman.EndpointReference, commandID, code string) error
	Disconnect(ctx context.Context, epr *wsman.EndpointReference) error
	Reconnect(ctx context.Context, shellID string) error
	Connect(ctx context.Context, shellID string, connectXML string) ([]byte, error)
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
	epr       *wsman.EndpointReference
	shellID   string // Kept for ShellID() compatibility and Reconnect
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

// EPR returns the EndpointReference for this pool.
func (b *WSManBackend) EPR() *wsman.EndpointReference {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.epr
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

	epr, err := b.client.Create(ctx, options, creationXML)
	if err != nil {
		return err
	}

	// Enforce the correct ResourceURI for PowerShell.
	// Some servers might return the generic WinRS URI in the Create response,
	// but subsequent commands must target the PowerShell URI.
	epr.ResourceURI = wsman.ResourceURIPowerShell

	b.epr = epr
	// Configure transport to use the new EPR
	b.transport.Configure(b.client, epr, "")

	// Extract ShellID from selectors for compatibility
	for _, s := range epr.Selectors {
		if s.Name == "ShellId" {
			b.shellID = s.Value
			break
		}
	}
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

	err := b.client.Delete(ctx, b.epr)
	if err != nil {
		return err
	}

	b.closed = true
	return nil
}

// PreparePipeline creates the WSMan command and returns a per-pipeline transport.

// Disconnect disconnects the WSMan shell.
func (b *WSManBackend) Disconnect(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.opened {
		return ErrPoolNotOpened
	}
	if b.closed {
		return ErrPoolClosed
	}

	// Call WSMan Disconnect
	if err := b.client.Disconnect(ctx, b.epr); err != nil {
		return err
	}

	// Mark as closed/disconnected locally (we can't use it anymore until reconnect)
	b.closed = true
	return nil
}

// Reconnect reconnects the WSMan shell.
// This is a stub for the interface, but typically Reconnect creates a new client state.
// Here we just proxy.
func (b *WSManBackend) Reconnect(ctx context.Context, shellID string) error {
	return b.client.Reconnect(ctx, shellID)
}

// Reattach connects to an existing disconnected shell using WSManConnectShellEx semantics.
// This is for NEW clients connecting to a session that was disconnected.
func (b *WSManBackend) Reattach(ctx context.Context, pool *runspace.Pool, shellID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.opened {
		return nil // Already opened
	}

	// 1. Get PSRP handshake fragments from pool (SessionCapability + ConnectRunspacePool)
	connectFrags, err := pool.GetConnectHandshakeFragments()
	if err != nil {
		return fmt.Errorf("get connect fragments: %w", err)
	}
	connectXML := base64.StdEncoding.EncodeToString(connectFrags)

	// 2. Send WSMan Connect (NOT Reconnect) with PSRP data piggybacked
	respData, err := b.client.Connect(ctx, shellID, connectXML)
	if err != nil {
		return fmt.Errorf("wsman connect: %w", err)
	}

	// 3. Reconstruct EPR for this session
	b.epr = &wsman.EndpointReference{
		ResourceURI: wsman.ResourceURIPowerShell,
		Selectors: []wsman.Selector{
			{Name: "ShellId", Value: shellID},
		},
	}
	// Configure transport to use the new EPR
	b.transport.Configure(b.client, b.epr, "")

	b.shellID = shellID
	b.opened = true

	// 4. Process the PSRP response data (contains CONNECT_RUNSPACEPOOL response + state)
	if len(respData) > 0 {
		if err := pool.ProcessConnectResponse(respData); err != nil {
			return fmt.Errorf("process connect response: %w", err)
		}
	}

	// 5. Mark pool as opened
	// Note: We do NOT start the dispatch loop here for WSMan.
	// WSMan uses per-pipeline receive loops via runPipelineReceive with specific CommandId.
	// The dispatch loop is for HvSocket where all data flows through one shared transport.
	pool.ResumeOpened()
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

	returnedID, err := b.client.Command(ctx, b.epr, pipelineID, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("create wsman command: %w", err)
	}

	// 2. Create a per-pipeline transport for receiving
	// Each pipeline gets its own transport with its specific commandID
	// This allows concurrent pipelines to receive independently
	pipelineTransport := NewWSManTransport(b.client, b.epr, returnedID)
	pipelineTransport.SetContext(ctx)

	// 3. Setup cleanup function
	cleanup := func() {
		// Terminate the command on WSMan side
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = b.client.Signal(ctx, b.epr, returnedID, wsman.SignalTerminate)
	}

	// 4. Skip PSRP Invoke Send
	// Since we sent the CreatePipeline message in the WSMan Command arguments,
	// we must tell go-psrpcore NOT to send it again over the transport.
	p.SkipInvokeSend()

	return pipelineTransport, cleanup, nil
}
