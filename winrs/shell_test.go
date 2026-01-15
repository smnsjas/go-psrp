package winrs

import (
	"context"
	"testing"

	"github.com/smnsjas/go-psrp/wsman"
)

// mockTransport implements Transport for testing.
type mockTransport struct {
	createFn  func(ctx context.Context, options map[string]string, xml string) (*wsman.EndpointReference, error)
	commandFn func(ctx context.Context, epr *wsman.EndpointReference, cmdID, args string) (string, error)
	sendFn    func(ctx context.Context, epr *wsman.EndpointReference, cmdID, stream string, data []byte) error
	receiveFn func(ctx context.Context, epr *wsman.EndpointReference, cmdID string) (*wsman.ReceiveResult, error)
	signalFn  func(ctx context.Context, epr *wsman.EndpointReference, cmdID, code string) error
	deleteFn  func(ctx context.Context, epr *wsman.EndpointReference) error
}

func (m *mockTransport) Create(ctx context.Context, options map[string]string, xml string) (*wsman.EndpointReference, error) {
	if m.createFn != nil {
		return m.createFn(ctx, options, xml)
	}
	return &wsman.EndpointReference{
		Selectors: []wsman.Selector{{Name: "ShellId", Value: "test-shell-id"}},
	}, nil
}

func (m *mockTransport) Command(ctx context.Context, epr *wsman.EndpointReference, cmdID, args string) (string, error) {
	if m.commandFn != nil {
		return m.commandFn(ctx, epr, cmdID, args)
	}
	return cmdID, nil
}

func (m *mockTransport) Send(ctx context.Context, epr *wsman.EndpointReference, cmdID, stream string, data []byte) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, epr, cmdID, stream, data)
	}
	return nil
}

func (m *mockTransport) Receive(ctx context.Context, epr *wsman.EndpointReference, cmdID string) (*wsman.ReceiveResult, error) {
	if m.receiveFn != nil {
		return m.receiveFn(ctx, epr, cmdID)
	}
	return &wsman.ReceiveResult{
		Stdout:   []byte("test output\n"),
		Stderr:   []byte{},
		ExitCode: 0,
		Done:     true,
	}, nil
}

func (m *mockTransport) Signal(ctx context.Context, epr *wsman.EndpointReference, cmdID, code string) error {
	if m.signalFn != nil {
		return m.signalFn(ctx, epr, cmdID, code)
	}
	return nil
}

func (m *mockTransport) Delete(ctx context.Context, epr *wsman.EndpointReference) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, epr)
	}
	return nil
}

func TestNewShell(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "default options",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "with working directory",
			opts:    []Option{WithWorkingDirectory("C:\\temp")},
			wantErr: false,
		},
		{
			name:    "with codepage",
			opts:    []Option{WithCodepage(65001)},
			wantErr: false,
		},
		{
			name:    "with no profile",
			opts:    []Option{WithNoProfile()},
			wantErr: false,
		},
		{
			name:    "with environment",
			opts:    []Option{WithEnvironment(map[string]string{"VAR": "value"})},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockTransport{}
			shell, err := NewShell(context.Background(), mock, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewShell() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if shell.ID() != "test-shell-id" {
					t.Errorf("shell.ID() = %q, want %q", shell.ID(), "test-shell-id")
				}
				if err := shell.Close(context.Background()); err != nil {
					t.Errorf("shell.Close() error = %v", err)
				}
			}
		})
	}
}

func TestNewShell_NilTransport(t *testing.T) {
	_, err := NewShell(context.Background(), nil)
	if err == nil {
		t.Error("NewShell(nil) expected error, got nil")
	}
}

func TestShell_Run(t *testing.T) {
	mock := &mockTransport{}
	shell, err := NewShell(context.Background(), mock)
	if err != nil {
		t.Fatalf("NewShell() error = %v", err)
	}
	defer func() {
		if closeErr := shell.Close(context.Background()); closeErr != nil {
			t.Errorf("Close error: %v", closeErr)
		}
	}()

	proc, err := shell.Run(context.Background(), "dir", "/b")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if string(proc.Stdout()) != "test output\n" {
		t.Errorf("Stdout = %q, want %q", proc.Stdout(), "test output\n")
	}
	if proc.ExitCode() != 0 {
		t.Errorf("ExitCode = %d, want 0", proc.ExitCode())
	}
}

func TestShell_Run_EmptyExecutable(t *testing.T) {
	mock := &mockTransport{}
	shell, err := NewShell(context.Background(), mock)
	if err != nil {
		t.Fatalf("NewShell() error = %v", err)
	}
	defer func() {
		if closeErr := shell.Close(context.Background()); closeErr != nil {
			t.Errorf("Close error: %v", closeErr)
		}
	}()

	_, err = shell.Run(context.Background(), "")
	if err != ErrInvalidExecutable {
		t.Errorf("Run(\"\") error = %v, want %v", err, ErrInvalidExecutable)
	}
}

func TestShell_ClosedShell(t *testing.T) {
	mock := &mockTransport{}
	shell, err := NewShell(context.Background(), mock)
	if err != nil {
		t.Fatalf("NewShell() error = %v", err)
	}

	// Close the shell
	if err := shell.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Try to run command on closed shell
	_, err = shell.Run(context.Background(), "dir")
	if err != ErrShellClosed {
		t.Errorf("Run on closed shell error = %v, want %v", err, ErrShellClosed)
	}

	// Close again should be no-op
	if err := shell.Close(context.Background()); err != nil {
		t.Errorf("Double Close() error = %v", err)
	}
}

func TestProcess_Signal(t *testing.T) {
	signalCalled := false
	mock := &mockTransport{
		signalFn: func(_ context.Context, _ *wsman.EndpointReference, _, code string) error {
			signalCalled = true
			if code != wsman.SignalCtrlC {
				t.Errorf("Signal code = %q, want %q", code, wsman.SignalCtrlC)
			}
			return nil
		},
	}
	shell, err := NewShell(context.Background(), mock)
	if err != nil {
		t.Fatalf("NewShell() error = %v", err)
	}
	defer func() {
		if closeErr := shell.Close(context.Background()); closeErr != nil {
			t.Errorf("Close error: %v", closeErr)
		}
	}()

	proc, err := shell.Start(context.Background(), "ping", "-t", "localhost")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if err := proc.Signal(context.Background(), wsman.SignalCtrlC); err != nil {
		t.Errorf("Signal() error = %v", err)
	}

	if !signalCalled {
		t.Error("Signal() did not call transport.Signal")
	}
}
