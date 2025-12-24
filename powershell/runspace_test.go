package powershell

import (
	"context"
	"testing"
)

// mockWSManClientForPool extends mockWSManClient for pool tests.
type mockWSManClientForPool struct {
	createShellID  string
	createErr      error
	deleteErr      error
	deleteCalled   bool
	deletedShellID string
}

func (m *mockWSManClientForPool) Create(_ context.Context, _ map[string]string) (string, error) {
	return m.createShellID, m.createErr
}

func (m *mockWSManClientForPool) Delete(_ context.Context, shellID string) error {
	m.deleteCalled = true
	m.deletedShellID = shellID
	return m.deleteErr
}

func (m *mockWSManClientForPool) Command(
	_ context.Context, _, _ string,
) (string, error) {
	return "cmd-id", nil
}

func (m *mockWSManClientForPool) Send(_ context.Context, _, _, _ string, _ []byte) error {
	return nil
}

func (m *mockWSManClientForPool) Receive(_ context.Context, _, _ string) (*ReceiveResult, error) {
	return &ReceiveResult{}, nil
}

func (m *mockWSManClientForPool) Signal(_ context.Context, _, _, _ string) error {
	return nil
}

// TestRunspacePool_Open verifies pool creation via WSMan Create.
func TestRunspacePool_Open(t *testing.T) {
	mock := &mockWSManClientForPool{
		createShellID: "test-shell-id",
	}
	pool := NewRunspacePool(mock)

	ctx := context.Background()
	err := pool.Open(ctx)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if pool.ShellID() != "test-shell-id" {
		t.Errorf("ShellID = %q, want %q", pool.ShellID(), "test-shell-id")
	}
}

// TestRunspacePool_Close verifies pool cleanup via WSMan Delete.
func TestRunspacePool_Close(t *testing.T) {
	mock := &mockWSManClientForPool{
		createShellID: "test-shell-id",
	}
	pool := NewRunspacePool(mock)

	ctx := context.Background()
	_ = pool.Open(ctx)

	err := pool.Close(ctx)
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

// TestRunspacePool_CreatePipeline verifies pipeline creation.
func TestRunspacePool_CreatePipeline(t *testing.T) {
	mock := &mockWSManClientForPool{
		createShellID: "test-shell-id",
	}
	pool := NewRunspacePool(mock)

	ctx := context.Background()
	_ = pool.Open(ctx)

	pipeline, err := pool.CreatePipeline(ctx)
	if err != nil {
		t.Fatalf("CreatePipeline failed: %v", err)
	}

	if pipeline == nil {
		t.Error("pipeline is nil")
	}
}

// TestRunspacePool_NotOpened verifies operations fail if pool not opened.
func TestRunspacePool_NotOpened(t *testing.T) {
	mock := &mockWSManClientForPool{}
	pool := NewRunspacePool(mock)

	ctx := context.Background()

	_, err := pool.CreatePipeline(ctx)
	if err == nil {
		t.Error("expected error when pool not opened")
	}

	err = pool.Close(ctx)
	if err == nil {
		t.Error("expected error when closing unopened pool")
	}
}
