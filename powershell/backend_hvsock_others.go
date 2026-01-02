//go:build !windows

// Package powershell provides PowerShell remoting via WSMan and HVSocket transports.
package powershell

import (
	"context"
	"errors"
	"io"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// HvSocketBackend is a stub for non-Windows platforms.
type HvSocketBackend struct{}

// NewHvSocketBackend creates a stub backend for non-Windows platforms.
func NewHvSocketBackend(_ uuid.UUID, _, _, _, _ string, _ uuid.UUID) *HvSocketBackend {
	return &HvSocketBackend{}
}

// Connect returns an error on non-Windows platforms.
func (b *HvSocketBackend) Connect(_ context.Context) error {
	return errors.New("hvsock is only supported on windows")
}

// Transport returns nil on non-Windows platforms.
func (b *HvSocketBackend) Transport() io.ReadWriter {
	return nil
}

// Init returns an error on non-Windows platforms.
func (b *HvSocketBackend) Init(_ context.Context, _ *runspace.Pool) error {
	return errors.New("hvsock is only supported on windows")
}

func (b *HvSocketBackend) PreparePipeline(ctx context.Context, p *pipeline.Pipeline, content string) (io.Reader, func(), error) {
	return nil, nil, errors.New("hvsock is only supported on windows")
}

// Close is a no-op on non-Windows platforms.
func (b *HvSocketBackend) Close(_ context.Context) error {
	return nil
}

// ShellID returns empty string on non-Windows platforms.
func (b *HvSocketBackend) ShellID() string {
	return ""
}
