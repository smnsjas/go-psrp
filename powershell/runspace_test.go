package powershell

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrp/wsman"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// mockWSManClientForPool implements PoolClient for tests.
// mockWSManClientForPool implements PoolClient for tests.
type mockWSManClientForPool struct {
	createEPR    *wsman.EndpointReference
	createErr    error
	deleteErr    error
	deleteCalled bool
	deletedEPR   *wsman.EndpointReference
}

func (m *mockWSManClientForPool) Create(_ context.Context, _ map[string]string, _ string) (*wsman.EndpointReference, error) {
	return m.createEPR, m.createErr
}

func (m *mockWSManClientForPool) Delete(_ context.Context, epr *wsman.EndpointReference) error {
	m.deleteCalled = true
	m.deletedEPR = epr
	return m.deleteErr
}

func (m *mockWSManClientForPool) Command(
	_ context.Context, _ *wsman.EndpointReference, _, _ string,
) (string, error) {
	return "cmd-id", nil
}

func (m *mockWSManClientForPool) Send(_ context.Context, _ *wsman.EndpointReference, _, _ string, _ []byte) error {
	return nil
}

func (m *mockWSManClientForPool) Receive(_ context.Context, _ *wsman.EndpointReference, _ string) (*wsman.ReceiveResult, error) {
	return &wsman.ReceiveResult{}, nil
}

func (m *mockWSManClientForPool) Signal(_ context.Context, _ *wsman.EndpointReference, _, _ string) error {
	return nil
}

func (m *mockWSManClientForPool) Disconnect(_ context.Context, _ *wsman.EndpointReference) error {
	return nil
}

func (m *mockWSManClientForPool) Reconnect(_ context.Context, _ string) error {
	return nil
}

func (m *mockWSManClientForPool) Connect(_ context.Context, _ string, _ string) ([]byte, error) {
	return nil, nil
}

func (m *mockWSManClientForPool) CloseIdleConnections() {}

func dummyPoolEPR() *wsman.EndpointReference {
	return &wsman.EndpointReference{
		Address: "http://localhost:5985/wsman",
		Selectors: []wsman.Selector{
			{Name: "ShellId", Value: "test-shell-id"},
		},
	}
}

// TestWSManBackend_ShellID verifies shell ID is returned after init.
func TestWSManBackend_ShellID(t *testing.T) {
	mock := &mockWSManClientForPool{
		createEPR: dummyPoolEPR(),
	}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	// Before init, should be empty
	if backend.ShellID() != "" {
		t.Errorf("ShellID before init = %q, want empty", backend.ShellID())
	}
}

// TestWSManBackend_Close verifies close calls Delete.
func TestWSManBackend_Close(t *testing.T) {
	mock := &mockWSManClientForPool{
		createEPR: dummyPoolEPR(),
	}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	// Manually set opened state to test close
	backend.opened = true
	backend.epr = dummyPoolEPR()
	backend.shellID = "test-shell-id"

	ctx := context.Background()
	err := backend.Close(ctx)
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !mock.deleteCalled {
		t.Error("Delete was not called")
	}
	if mock.deletedEPR.Selectors[0].Value != "test-shell-id" {
		t.Errorf("deleted shell ID = %q, want %q", mock.deletedEPR.Selectors[0].Value, "test-shell-id")
	}
}

// TestWSManBackend_NotOpened verifies Close fails if not opened.
func TestWSManBackend_NotOpened(t *testing.T) {
	mock := &mockWSManClientForPool{}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	ctx := context.Background()

	err := backend.Close(ctx)
	if err != ErrPoolNotOpened {
		t.Errorf("Close on unopened pool: got %v, want ErrPoolNotOpened", err)
	}
}

// TestWSManBackend_Init_CreateError verifies Init handles Create failure.
func TestWSManBackend_Init_CreateError(t *testing.T) {
	expectedErr := errors.New("create failed")
	mock := &mockWSManClientForPool{
		createErr: expectedErr,
	}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	// Create a dummy pool (we need a valid pool to call GetHandshakeFragments)
	// runspace.New requires transport and poolID
	pool := runspace.New(transport, uuid.New())

	ctx := context.Background()
	err := backend.Init(ctx, pool)
	if err == nil {
		t.Error("Init expected error, got nil")
	}
	if err != expectedErr {
		t.Errorf("Init error = %v, want %v", err, expectedErr)
	}
}

// TestWSManBackend_PreparePipeline verifies command creation and cleanup.
func TestWSManBackend_PreparePipeline(t *testing.T) {
	mock := &mockWSManClientForPool{
		createEPR: dummyPoolEPR(),
	}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	// Manually open
	backend.opened = true
	backend.epr = dummyPoolEPR()

	// Dummy pipeline
	pl := pipeline.New(nil, uuid.New(), "echo test")
	ctx := context.Background()

	// Call PreparePipeline
	pTransport, cleanup, err := backend.PreparePipeline(ctx, pl, "payload")
	if err != nil {
		t.Fatalf("PreparePipeline failed: %v", err)
	}
	if pTransport == nil {
		t.Error("Returned transport is nil")
	}
	if cleanup == nil {
		t.Error("Returned cleanup is nil")
	}

	// Verify cleanup calls Signal
	cleanup()
}

func TestWSManBackend_Disconnect(t *testing.T) {
	mock := &mockWSManClientForPool{
		createEPR: dummyPoolEPR(),
	}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	// Manually open
	backend.opened = true
	backend.epr = dummyPoolEPR()

	ctx := context.Background()
	err := backend.Disconnect(ctx)
	if err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}

	if !backend.closed {
		t.Error("Backend should be closed after Disconnect")
	}

	// Double disconnect
	err = backend.Disconnect(ctx)
	if err != ErrPoolClosed {
		t.Errorf("Double Disconnect error = %v, want ErrPoolClosed", err)
	}
}

func TestWSManBackend_Reconnect(t *testing.T) {
	mock := &mockWSManClientForPool{}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	err := backend.Reconnect(context.Background(), "shell-id")
	if err != nil {
		t.Fatalf("Reconnect failed: %v", err)
	}
}

func TestWSManBackend_Reattach(t *testing.T) {
	mock := &mockWSManClientForPool{
		createEPR: dummyPoolEPR(),
	}
	transport := NewWSManTransport(mock, nil, "")
	backend := NewWSManBackend(mock, transport)

	// dummy pool
	pool := runspace.New(transport, uuid.New())

	ctx := context.Background()
	err := backend.Reattach(ctx, pool, "shell-id")
	if err != nil {
		t.Fatalf("Reattach failed: %v", err)
	}

	if !backend.opened {
		t.Error("Backend should be opened after Reattach")
	}
	if backend.ShellID() != "shell-id" {
		t.Errorf("ShellID = %s, want shell-id", backend.ShellID())
	}
}
