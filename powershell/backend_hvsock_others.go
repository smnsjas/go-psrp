//go:build !windows

package powershell

import (
	"context"
	"errors"
	"io"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

type HvSocketBackend struct{}

// NewHvSocketBackend creates a stub backend.
func NewHvSocketBackend(vmID uuid.UUID, domain, username, password, configName string, poolID uuid.UUID) *HvSocketBackend {
	return &HvSocketBackend{}
}

func (b *HvSocketBackend) Connect(ctx context.Context) error {
	return errors.New("hvsock is only supported on windows")
}

func (b *HvSocketBackend) Transport() io.ReadWriter {
	return nil
}

func (b *HvSocketBackend) Init(ctx context.Context, pool *runspace.Pool) error {
	return errors.New("hvsock is only supported on windows")
}

func (b *HvSocketBackend) PreparePipeline(ctx context.Context, p *pipeline.Pipeline, payload string) (func(), error) {
	return nil, errors.New("hvsock is only supported on windows")
}

func (b *HvSocketBackend) Close(ctx context.Context) error {
	return nil
}

func (b *HvSocketBackend) ShellID() string {
	return ""
}
