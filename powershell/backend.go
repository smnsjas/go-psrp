package powershell

import (
	"context"
	"io"

	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// RunspaceBackend abstracts the transport-specific logic for a PSRP runspace.
// Different backends (WSMan vs HvSocket) require different initialization
// and pipeline execution strategies.
type RunspaceBackend interface {
	// Close terminates the backend connection.
	Close(ctx context.Context) error

	// Connect establishes the physical connection (if relevant) and prepares the transport.
	Connect(ctx context.Context) error

	// Transport returns the io.ReadWriter to be used by go-psrpcore.
	// Must be called after Connect.
	Transport() io.ReadWriter

	// Init initializes the PSRP runspace pool with the backend.
	// This includes establishing the connection and performing any necessary handshakes.
	Init(ctx context.Context, pool *runspace.Pool) error

	// PreparePipeline creates the transport for a specific pipeline.
	// This is called before the pipeline is invoked.
	// payload represents the CreatePipeline message payload (base64 encoded) required by WSMan.
	// Returns:
	// - pipelineTransport: io.Reader for receiving this pipeline's output (for WSMan, a per-command transport)
	// - cleanup: function to call after the pipeline completes
	// - error: any error during setup
	PreparePipeline(ctx context.Context, p *pipeline.Pipeline, payload string) (io.Reader, func(), error)

	// ShellID returns the identifier of the underlying shell/runspace.
	ShellID() string
}
