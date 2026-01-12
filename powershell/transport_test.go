package powershell

import (
	"context"
	"testing"

	"github.com/smnsjas/go-psrp/wsman"
)

// reused mockWSManClientForPool from runspace_test.go?
// No, runspace_test.go is same package "powershell".
// So mockWSManClientForPool is available if it's in runspace_test.go.
// Step 622 showed it is there.

// TestWSManTransport_Configure verifies Configure updates EPR and CommandID.
func TestWSManTransport_Configure(t *testing.T) {
	mock := &mockWSManClientForPool{}
	transport := NewWSManTransport(mock, nil, "initial-cmd")

	if transport.client != mock {
		t.Error("Client not set")
	}

	newEPR := dummyPoolEPR()
	transport.Configure(mock, newEPR, "new-cmd")

	if transport.epr != newEPR {
		t.Error("EPR not updated")
	}
	if transport.commandID != "new-cmd" {
		t.Errorf("CommandID = %q, want new-cmd", transport.commandID)
	}
}

// TestWSManTransport_Write verifies Write calls Send.
func TestWSManTransport_Write(t *testing.T) {
	// We need a mock that tracks Send calls
	mock := &mockWSManClientForPool{}
	// But mockWSManClientForPool.Send is a stub returning nil.
	// We just want to ensure it compiles and runs without panic for now
	// as we test deeper logic in TestWSManTransport_Write_Success
	transport := NewWSManTransport(mock, nil, "cmd-1")
	if transport == nil {
		t.Error("Transport is nil")
	}
}

type mockTransportClient struct {
	sendFunc    func(ctx context.Context, epr *wsman.EndpointReference, commandID, stream string, data []byte) error
	receiveFunc func(ctx context.Context, epr *wsman.EndpointReference, commandID string) (*wsman.ReceiveResult, error)
	// Embed the basic mock for others
	mockWSManClientForPool
}

func (m *mockTransportClient) Send(ctx context.Context, epr *wsman.EndpointReference, commandID, stream string, data []byte) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, epr, commandID, stream, data)
	}
	return m.mockWSManClientForPool.Send(ctx, epr, commandID, stream, data)
}

func (m *mockTransportClient) Receive(ctx context.Context, epr *wsman.EndpointReference, commandID string) (*wsman.ReceiveResult, error) {
	if m.receiveFunc != nil {
		return m.receiveFunc(ctx, epr, commandID)
	}
	return m.mockWSManClientForPool.Receive(ctx, epr, commandID)
}

func TestWSManTransport_Write_Success(t *testing.T) {
	var capturedData []byte
	mock := &mockTransportClient{
		sendFunc: func(ctx context.Context, epr *wsman.EndpointReference, commandID, stream string, data []byte) error {
			capturedData = data
			return nil
		},
	}

	transport := NewWSManTransport(mock, dummyPoolEPR(), "cmd-1")

	data := []byte("some-data")
	n, err := transport.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Written bytes = %d, want %d", n, len(data))
	}
	if string(capturedData) != string(data) {
		t.Errorf("Captured data = %q, want %q", capturedData, data)
	}
}

func TestWSManTransport_Read_Success(t *testing.T) {
	mock := &mockTransportClient{
		receiveFunc: func(ctx context.Context, epr *wsman.EndpointReference, commandID string) (*wsman.ReceiveResult, error) {
			return &wsman.ReceiveResult{
				Stdout: []byte("response"),
			}, nil
		},
	}

	transport := NewWSManTransport(mock, dummyPoolEPR(), "cmd-1")
	buf := make([]byte, 100)
	n, err := transport.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 8 { // "response"
		t.Errorf("Read n = %d, want 8", n)
	}
	if string(buf[:n]) != "response" {
		t.Errorf("Read data = %q, want response", buf[:n])
	}
}

func TestWSManTransport_Close(t *testing.T) {
	mock := &mockTransportClient{
		// Default mock returns nil for everything relevant (Disconnect, Delete, Signal)
	}
	transport := NewWSManTransport(mock, dummyPoolEPR(), "cmd-1")
	err := transport.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestWSManTransport_CloseIdleConnections(t *testing.T) {
	mock := &mockTransportClient{}
	transport := NewWSManTransport(mock, dummyPoolEPR(), "cmd-1")
	// Just ensure it doesn't panic
	transport.CloseIdleConnections()
}

func TestPipeline_Methods(t *testing.T) {
	mock := &mockTransportClient{}
	p := &Pipeline{
		client:    mock,
		epr:       dummyPoolEPR(),
		commandID: "cmd-id",
	}

	if p.CommandID() != "cmd-id" {
		t.Errorf("CommandID = %q, want cmd-id", p.CommandID())
	}

	adapter := p.GetAdapter()
	if adapter == nil {
		t.Fatal("GetAdapter returned nil")
	}
	if adapter.commandID != "cmd-id" {
		t.Errorf("Adapter commandID = %q, want cmd-id", adapter.commandID)
	}

	if err := p.Close(context.Background()); err != nil {
		t.Errorf("Close error = %v", err)
	}
}
