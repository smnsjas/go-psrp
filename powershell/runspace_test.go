package powershell

import (
	"context"
	"testing"

	"github.com/smnsjas/go-psrp/wsman"
)

// mockWSManClientForPool implements PoolClient for tests.
type mockWSManClientForPool struct {
	createShellID  string
	createErr      error
	deleteErr      error
	deleteCalled   bool
	deletedShellID string
}

func (m *mockWSManClientForPool) Create(_ context.Context, _ map[string]string, _ string) (string, error) {
	return m.createShellID, m.createErr
}

func (m *mockWSManClientForPool) Delete(_ context.Context, shellID string) error {
	m.deleteCalled = true
	m.deletedShellID = shellID
	return m.deleteErr
}

func (m *mockWSManClientForPool) Command(
	_ context.Context, _, _, _ string,
) (string, error) {
	return "cmd-id", nil
}

func (m *mockWSManClientForPool) Send(_ context.Context, _, _, _ string, _ []byte) error {
	return nil
}

func (m *mockWSManClientForPool) Receive(_ context.Context, _, _ string) (*wsman.ReceiveResult, error) {
	return &wsman.ReceiveResult{}, nil
}

func (m *mockWSManClientForPool) Signal(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *mockWSManClientForPool) CloseIdleConnections() {}

// TestWSManBackend_ShellID verifies shell ID is returned after init.
func TestWSManBackend_ShellID(t *testing.T) {
	mock := &mockWSManClientForPool{
		createShellID: "test-shell-id",
	}
	transport := NewWSManTransport(mock, "", "")
	backend := NewWSManBackend(mock, transport)

	// Before init, should be empty
	if backend.ShellID() != "" {
		t.Errorf("ShellID before init = %q, want empty", backend.ShellID())
	}
}

// TestWSManBackend_Close verifies close calls Delete.
func TestWSManBackend_Close(t *testing.T) {
	mock := &mockWSManClientForPool{
		createShellID: "test-shell-id",
	}
	transport := NewWSManTransport(mock, "", "")
	backend := NewWSManBackend(mock, transport)

	// Manually set opened state to test close
	backend.opened = true
	backend.shellID = "test-shell-id"

	ctx := context.Background()
	err := backend.Close(ctx)
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !mock.deleteCalled {
		t.Error("Delete was not called")
	}
	if mock.deletedShellID != "test-shell-id" {
		t.Errorf("deleted shell ID = %q, want %q", mock.deletedShellID, "test-shell-id")
	}
}

// TestWSManBackend_NotOpened verifies Close fails if not opened.
func TestWSManBackend_NotOpened(t *testing.T) {
	mock := &mockWSManClientForPool{}
	transport := NewWSManTransport(mock, "", "")
	backend := NewWSManBackend(mock, transport)

	ctx := context.Background()

	err := backend.Close(ctx)
	if err != ErrPoolNotOpened {
		t.Errorf("Close on unopened pool: got %v, want ErrPoolNotOpened", err)
	}
}
