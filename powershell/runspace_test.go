package powershell

import (
	"context"
	"testing"

	"github.com/smnsjas/go-psrp/wsman"
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
