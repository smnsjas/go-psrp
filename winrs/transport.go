package winrs

import (
	"context"

	"github.com/smnsjas/go-psrp/wsman"
)

// Transport abstracts WSMan operations for WinRS shells.
// This interface enables testing with mock implementations.
type Transport interface {
	// Create creates a new shell and returns its endpoint reference.
	Create(ctx context.Context, options map[string]string, creationXML string) (*wsman.EndpointReference, error)

	// Command creates a command in the shell and returns the command ID.
	Command(ctx context.Context, epr *wsman.EndpointReference, commandID, arguments string) (string, error)

	// Send sends data to a command's input stream.
	Send(ctx context.Context, epr *wsman.EndpointReference, commandID, stream string, data []byte) error

	// Receive retrieves output from a command.
	Receive(ctx context.Context, epr *wsman.EndpointReference, commandID string) (*wsman.ReceiveResult, error)

	// Signal sends a signal to a command.
	Signal(ctx context.Context, epr *wsman.EndpointReference, commandID, code string) error

	// Delete deletes a shell.
	Delete(ctx context.Context, epr *wsman.EndpointReference) error
}

// Ensure *wsman.Client implements Transport.
var _ Transport = (*wsman.Client)(nil)
