package powershell

import (
	"context"
)

// Pipeline represents a PowerShell pipeline running in a RunspacePool.
type Pipeline struct {
	client    PoolClient
	shellID   string
	commandID string
}

// CommandID returns the WSMan command ID for this pipeline.
func (p *Pipeline) CommandID() string {
	return p.commandID
}

// GetAdapter returns an io.ReadWriter adapter for this pipeline.
// This can be passed to go-psrpcore's runspace.New() as the transport.
func (p *Pipeline) GetAdapter() *Adapter {
	return &Adapter{
		client:    p.client,
		shellID:   p.shellID,
		commandID: p.commandID,
		ctx:       context.Background(),
	}
}

// Close terminates this pipeline.
func (p *Pipeline) Close(ctx context.Context) error {
	return p.client.Signal(ctx, p.shellID, p.commandID, SignalTerminate)
}

// SignalTerminate is the signal code to terminate a command.
const SignalTerminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"
