package powershell

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/smnsjas/go-psrp/wsman"
)

// mockWSManClient is a test double for WSMan operations.
type mockWSManClient struct {
	sendData    []byte
	receiveData []byte
	receiveDone bool
}

func (m *mockWSManClient) Send(_ context.Context, _ *wsman.EndpointReference, _, _ string, data []byte) error {
	m.sendData = append(m.sendData, data...)
	return nil
}

func (m *mockWSManClient) Receive(_ context.Context, _ *wsman.EndpointReference, _ string) (*wsman.ReceiveResult, error) {
	return &wsman.ReceiveResult{
		Stdout: m.receiveData,
		Done:   m.receiveDone,
	}, nil
}

func dummyEPR() *wsman.EndpointReference {
	return &wsman.EndpointReference{
		Address: "http://localhost:5985/wsman",
		Selectors: []wsman.Selector{
			{Name: "ShellId", Value: "test-shell-id"},
		},
	}
}

// TestAdapter_Write verifies data is sent via WSMan Send.
func TestAdapter_Write(t *testing.T) {
	mock := &mockWSManClient{}
	adapter := NewAdapter(mock, dummyEPR(), "command-id")

	data := []byte("test-psrp-fragment")
	n, err := adapter.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	if !bytes.Equal(mock.sendData, data) {
		t.Errorf("sendData = %q, want %q", mock.sendData, data)
	}
}

// TestAdapter_Read verifies data is received via WSMan Receive.
func TestAdapter_Read(t *testing.T) {
	mock := &mockWSManClient{
		receiveData: []byte("response-data"),
		receiveDone: false,
	}
	adapter := NewAdapter(mock, dummyEPR(), "command-id")

	buf := make([]byte, 1024)
	n, err := adapter.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n != len(mock.receiveData) {
		t.Errorf("Read returned %d, want %d", n, len(mock.receiveData))
	}

	if !bytes.Equal(buf[:n], mock.receiveData) {
		t.Errorf("buf = %q, want %q", buf[:n], mock.receiveData)
	}
}

// TestAdapter_Read_EOF verifies EOF when command completes.
func TestAdapter_Read_EOF(t *testing.T) {
	mock := &mockWSManClient{
		receiveData: nil,
		receiveDone: true,
	}
	adapter := NewAdapter(mock, dummyEPR(), "command-id")

	buf := make([]byte, 1024)
	_, err := adapter.Read(buf)
	if err != io.EOF {
		t.Errorf("Read error = %v, want io.EOF", err)
	}
}

// TestAdapter_Read_BufferedData verifies buffered data is returned first.
func TestAdapter_Read_BufferedData(t *testing.T) {
	mock := &mockWSManClient{
		receiveData: []byte("more-data"),
	}
	adapter := NewAdapter(mock, dummyEPR(), "command-id")

	// First read should get initial data
	buf := make([]byte, 5) // Smaller than response
	n, err := adapter.Read(buf)
	if err != nil {
		t.Fatalf("First Read failed: %v", err)
	}
	if n != 5 {
		t.Errorf("First Read returned %d, want 5", n)
	}

	// Update mock for second read
	mock.receiveData = []byte("second")

	// Second read should get remaining buffered data + poll for more
	n, err = adapter.Read(buf)
	if err != nil {
		t.Fatalf("Second Read failed: %v", err)
	}
	// Should get remaining "-dat" from first read's buffer
	if n == 0 {
		t.Error("Second Read returned 0 bytes")
	}
}

// TestAdapter_Context verifies context cancellation.
func TestAdapter_Context(t *testing.T) {
	mock := &mockWSManClient{}
	adapter := NewAdapter(mock, dummyEPR(), "command-id")

	// Cancel the context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	adapter.SetContext(ctx)

	time.Sleep(10 * time.Millisecond)

	_, err := adapter.Read(make([]byte, 1024))
	if err == nil {
		t.Error("expected context deadline exceeded error")
	}
}

// TestAdapter_ImplementsReadWriter verifies interface compliance.
func TestAdapter_ImplementsReadWriter(_ *testing.T) {
	var _ io.ReadWriter = (*Adapter)(nil)
}
