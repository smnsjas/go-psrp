package powershell

import (
	"context"

	"github.com/smnsjas/go-psrp/wsman"
)

// Pipeline represents a PowerShell pipeline running in a RunspacePool.
type Pipeline struct {
	client    PoolClient
	epr       *wsman.EndpointReference
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
		epr:       p.epr,
		commandID: p.commandID,
		ctx:       context.Background(),
	}
}

// Close terminates this pipeline.
func (p *Pipeline) Close(ctx context.Context) error {
	return p.client.Signal(ctx, p.epr, p.commandID, SignalTerminate)
}

// SignalTerminate is the signal code to terminate a command.
const SignalTerminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"
