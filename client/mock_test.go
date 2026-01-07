package client

import (
	"context"
	"io"
	"sync"

	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// MockBackend is a mock implementation of powershell.RunspaceBackend
type MockBackend struct {
	mu sync.Mutex

	// Expectations
	ConnectFunc               func(ctx context.Context) error
	CloseFunc                 func(ctx context.Context) error
	InitFunc                  func(ctx context.Context, pool *runspace.Pool) error
	PrepareFunc               func(ctx context.Context, p *pipeline.Pipeline, payload string) (io.Reader, func(), error)
	ShellIDFunc               func() string
	ReattachFunc              func(ctx context.Context, pool *runspace.Pool, shellID string) error
	TransportFunc             func() io.ReadWriter
	SupportsPSRPKeepaliveFunc func() bool

	// State
	Connected bool
	Closed    bool
}

func (m *MockBackend) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ConnectFunc != nil {
		return m.ConnectFunc(ctx)
	}
	m.Connected = true
	return nil
}

func (m *MockBackend) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CloseFunc != nil {
		return m.CloseFunc(ctx)
	}
	m.Closed = true
	return nil
}

func (m *MockBackend) Transport() io.ReadWriter {
	if m.TransportFunc != nil {
		return m.TransportFunc()
	}
	// Return a no-op transport so RunspacePool doesn't panic on nil
	return &noOpTransport{}
}

func (m *MockBackend) Init(ctx context.Context, pool *runspace.Pool) error {
	if m.InitFunc != nil {
		return m.InitFunc(ctx, pool)
	}
	return nil
}

func (m *MockBackend) PreparePipeline(ctx context.Context, p *pipeline.Pipeline, payload string) (io.Reader, func(), error) {
	if m.PrepareFunc != nil {
		return m.PrepareFunc(ctx, p, payload)
	}
	// Default mock behavior
	return nil, func() {}, nil
}

func (m *MockBackend) ShellID() string {
	if m.ShellIDFunc != nil {
		return m.ShellIDFunc()
	}
	return "mock-shell-id"
}

func (m *MockBackend) Reattach(ctx context.Context, pool *runspace.Pool, shellID string) error {
	if m.ReattachFunc != nil {
		return m.ReattachFunc(ctx, pool, shellID)
	}
	return nil
}

func (m *MockBackend) SupportsPSRPKeepalive() bool {
	if m.SupportsPSRPKeepaliveFunc != nil {
		return m.SupportsPSRPKeepaliveFunc()
	}
	return false
}

// noOpTransport implements io.ReadWriter but does nothing
type noOpTransport struct{}

func (t *noOpTransport) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

func (t *noOpTransport) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// Mock transport to simulate PSRP fragmentation if needed
type MockTransport struct {
	io.ReadWriter
}
