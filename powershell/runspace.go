package powershell

import (
	"context"
	"errors"
	"sync"

	"github.com/smnsjas/go-psrp/wsman"
)

// PoolClient defines the WSMan operations needed by RunspacePool.
type PoolClient interface {
	Create(ctx context.Context, options map[string]string, creationXml string) (string, error)
	Delete(ctx context.Context, shellID string) error
	Command(ctx context.Context, shellID, commandID, arguments string) (string, error)
	Send(ctx context.Context, shellID, commandID, stream string, data []byte) error
	Receive(ctx context.Context, shellID, commandID string) (*wsman.ReceiveResult, error)
	Signal(ctx context.Context, shellID, commandID, code string) error
}

// Errors for RunspacePool operations.
var (
	ErrPoolNotOpened = errors.New("runspace pool not opened")
	ErrPoolClosed    = errors.New("runspace pool already closed")
)

// RunspacePool manages a PowerShell runspace pool over WSMan.
// It wraps the lifecycle of a WSMan shell and provides methods for
// creating and managing PowerShell pipelines.
type RunspacePool struct {
	mu sync.RWMutex

	client  PoolClient
	shellID string
	opened  bool
	closed  bool
}

// NewRunspacePool creates a new RunspacePool using the given WSMan client.
func NewRunspacePool(client PoolClient) *RunspacePool {
	return &RunspacePool{
		client: client,
	}
}

// ShellID returns the WSMan shell ID for this pool.
func (p *RunspacePool) ShellID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.shellID
}

// Open creates the WSMan shell and initializes the runspace pool.
func (p *RunspacePool) Open(ctx context.Context, creationXml string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrPoolClosed
	}
	if p.opened {
		return nil // Already opened
	}

	// Add protocolversion option as required by PSRP
	options := map[string]string{
		"protocolversion": "2.3",
	}

	shellID, err := p.client.Create(ctx, options, creationXml)
	if err != nil {
		return err
	}

	p.shellID = shellID
	p.opened = true
	return nil
}

// Close terminates all pipelines and closes the WSMan shell.
func (p *RunspacePool) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.opened {
		return ErrPoolNotOpened
	}
	if p.closed {
		return nil // Already closed
	}

	err := p.client.Delete(ctx, p.shellID)
	if err != nil {
		return err
	}

	p.closed = true
	return nil
}

// CreatePipeline creates a new PowerShell pipeline in this pool.
func (p *RunspacePool) CreatePipeline(ctx context.Context) (*Pipeline, error) {
	return p.CreatePipelineWithArgs(ctx, "", "")
}

// CreatePipelineWithArgs creates a new PowerShell pipeline with the given CommandID and Arguments.
// For PSRP over WSMan, the commandID should match the go-psrpcore Pipeline ID, and
// the arguments should contain the base64-encoded CreatePipeline fragment.
func (p *RunspacePool) CreatePipelineWithArgs(ctx context.Context, commandID, arguments string) (*Pipeline, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.opened {
		return nil, ErrPoolNotOpened
	}
	if p.closed {
		return nil, ErrPoolClosed
	}

	returnedID, err := p.client.Command(ctx, p.shellID, commandID, arguments)
	if err != nil {
		return nil, err
	}

	return &Pipeline{
		client:    p.client,
		shellID:   p.shellID,
		commandID: returnedID,
	}, nil
}
