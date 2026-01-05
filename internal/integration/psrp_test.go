package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/fragments"
	"github.com/smnsjas/go-psrpcore/messages"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// MockPSRPTransport simulates WSMan transport for testing go-psrpcore integration.
// It captures outgoing PSRP fragments and provides mock responses.
type MockPSRPTransport struct {
	mu sync.Mutex

	// Read buffer for responses
	readBuf bytes.Buffer

	// Pool ID
	poolID uuid.UUID

	// Fragment counter for responses
	objectID uint64

	// Closed channel - closed when transport is shut down
	closedCh chan struct{}
}

// NewMockPSRPTransport creates a mock transport with proper response handling.
func NewMockPSRPTransport(poolID uuid.UUID) *MockPSRPTransport {
	return &MockPSRPTransport{
		poolID:   poolID,
		closedCh: make(chan struct{}),
	}
}

// Write captures PSRP fragments sent by the client.
func (m *MockPSRPTransport) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Parse the fragment to understand what was sent
	if len(p) >= fragments.HeaderSize {
		frag, err := fragments.Decode(p)
		if err == nil {
			// Decode the PSRP message inside
			if len(frag.Data) >= messages.HeaderSize {
				msg, err := messages.Decode(frag.Data)
				if err == nil {
					// Generate appropriate response based on message type
					m.generateResponse(msg)
				}
			}
		}
	}

	return len(p), nil
}

// Read returns mock PSRP responses.
// Blocks if no data available until transport is closed.
func (m *MockPSRPTransport) Read(p []byte) (int, error) {
	for {
		m.mu.Lock()
		if m.readBuf.Len() > 0 {
			n, err := m.readBuf.Read(p)
			m.mu.Unlock()
			return n, err
		}
		m.mu.Unlock()

		// Wait for data or close
		select {
		case <-m.closedCh:
			return 0, io.EOF
		case <-time.After(10 * time.Millisecond):
			// Poll again
		}
	}
}

// Close shuts down the mock transport.
func (m *MockPSRPTransport) Close() {
	select {
	case <-m.closedCh:
		// Already closed
	default:
		close(m.closedCh)
	}
}

// generateResponse creates appropriate PSRP responses based on the request.
func (m *MockPSRPTransport) generateResponse(msg *messages.Message) {
	switch msg.Type {
	case messages.MessageTypeSessionCapability:
		m.queueSessionCapabilityResponse()
	case messages.MessageTypeInitRunspacePool:
		m.queueRunspacePoolStateResponse()
	case messages.MessageTypeCreatePipeline:
		// Queue PIPELINE_STATE (Running) then (Completed) responses
		m.queuePipelineStateResponse(msg.PipelineID, messages.PipelineStateRunning)
		m.queuePipelineOutputResponse(msg.PipelineID, "Hello from mock!")
		m.queuePipelineStateResponse(msg.PipelineID, messages.PipelineStateCompleted)
	}
}

// queuePipelineStateResponse adds a PIPELINE_STATE response.
func (m *MockPSRPTransport) queuePipelineStateResponse(pipelineID uuid.UUID, state messages.PipelineState) {
	// State data as CLIXML - just the state integer
	stateData := []byte(fmt.Sprintf(
		`<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">`+
			`<Obj RefId="0"><MS><I32 N="PipelineState">%d</I32></MS></Obj></Objs>`,
		state))

	msg := &messages.Message{
		Destination: messages.DestinationClient,
		Type:        messages.MessageTypePipelineState,
		RunspaceID:  m.poolID,
		PipelineID:  pipelineID,
		Data:        stateData,
	}

	m.queueMessage(msg)
}

// queuePipelineOutputResponse adds a PIPELINE_OUTPUT response with mock data.
func (m *MockPSRPTransport) queuePipelineOutputResponse(pipelineID uuid.UUID, output string) {
	// Output as serialized string
	outputData := []byte(fmt.Sprintf(
		`<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S>%s</S></Objs>`,
		output))

	msg := &messages.Message{
		Destination: messages.DestinationClient,
		Type:        messages.MessageTypePipelineOutput,
		RunspaceID:  m.poolID,
		PipelineID:  pipelineID,
		Data:        outputData,
	}

	m.queueMessage(msg)
}

// queueSessionCapabilityResponse adds a SESSION_CAPABILITY response.
func (m *MockPSRPTransport) queueSessionCapabilityResponse() {
	// Server capability response CLIXML
	capData := []byte(`<Obj RefId="0"><MS>` +
		`<Version N="protocolversion">2.3</Version>` +
		`<Version N="PSVersion">5.1</Version>` +
		`<Version N="SerializationVersion">1.1.0.1</Version>` +
		`</MS></Obj>`)

	msg := &messages.Message{
		Destination: messages.DestinationClient,
		Type:        messages.MessageTypeSessionCapability,
		RunspaceID:  m.poolID,
		PipelineID:  uuid.Nil,
		Data:        capData,
	}

	m.queueMessage(msg)
}

// queueRunspacePoolStateResponse adds a RUNSPACEPOOL_STATE (Opened) response.
func (m *MockPSRPTransport) queueRunspacePoolStateResponse() {
	// State = 2 (Opened) per MS-PSRP 2.2.2.2
	stateData := []byte(`<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">` +
		`<I32>2</I32></Objs>`)

	msg := &messages.Message{
		Destination: messages.DestinationClient,
		Type:        messages.MessageTypeRunspacePoolState,
		RunspaceID:  m.poolID,
		PipelineID:  uuid.Nil,
		Data:        stateData,
	}

	m.queueMessage(msg)
}

// queueMessage encodes and queues a PSRP message as fragments.
func (m *MockPSRPTransport) queueMessage(msg *messages.Message) {
	msgBytes, err := msg.Encode()
	if err != nil {
		return
	}

	// Create a single fragment (message is small enough)
	frag := &fragments.Fragment{
		ObjectID:   m.objectID,
		FragmentID: 0,
		Start:      true,
		End:        true,
		Data:       msgBytes,
	}
	m.objectID++

	fragBytes, err := frag.Encode()
	if err != nil {
		return // Should not happen with small test data
	}
	m.readBuf.Write(fragBytes)
}

// TestMockTransport_ImplementsReadWriter verifies interface compliance.
func TestMockTransport_ImplementsReadWriter(_ *testing.T) {
	var _ io.ReadWriter = (*MockPSRPTransport)(nil)
}

// TestPSRPCore_PoolCreation tests creating a Pool with mock transport.
func TestPSRPCore_PoolCreation(t *testing.T) {
	poolID := uuid.New()
	transport := NewMockPSRPTransport(poolID)

	pool := runspace.New(transport, poolID)
	if pool == nil {
		t.Fatal("runspace.New returned nil")
	}

	if pool.State() != runspace.StateBeforeOpen {
		t.Errorf("State = %v, want StateBeforeOpen", pool.State())
	}
}

// TestPSRPCore_PoolOpen tests the full Pool.Open() handshake.
func TestPSRPCore_PoolOpen(t *testing.T) {
	poolID := uuid.New()
	transport := NewMockPSRPTransport(poolID)

	pool := runspace.New(transport, poolID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open should complete successfully with proper mock responses
	err := pool.Open(ctx)
	if err != nil {
		t.Errorf("Open failed: %v", err)
	}

	if pool.State() != runspace.StateOpened {
		t.Errorf("State = %v, want StateOpened", pool.State())
	}
}

// TestPSRPCore_PoolOpenClose tests full lifecycle.
func TestPSRPCore_PoolOpenClose(t *testing.T) {
	poolID := uuid.New()
	transport := NewMockPSRPTransport(poolID)

	pool := runspace.New(transport, poolID)

	ctx := context.Background()

	err := pool.Open(ctx)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	err = pool.Close(ctx)
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Close the mock transport to allow dispatch loop to exit cleanly
	transport.Close()

	// Give cleanup a moment to complete
	time.Sleep(50 * time.Millisecond)

	if pool.State() != runspace.StateClosed {
		t.Errorf("State = %v, want StateClosed", pool.State())
	}
}

// TestMockPSRPTransport_GeneratesResponses verifies the mock generates correct responses.
func TestMockPSRPTransport_GeneratesResponses(t *testing.T) {
	poolID := uuid.New()
	transport := NewMockPSRPTransport(poolID)

	// Manually create a SESSION_CAPABILITY message
	capMsg := &messages.Message{
		Destination: messages.DestinationServer,
		Type:        messages.MessageTypeSessionCapability,
		RunspaceID:  poolID,
		PipelineID:  uuid.Nil,
		Data:        []byte(`<test/>`),
	}

	// Encode and write it
	msgBytes, err := capMsg.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	frag := &fragments.Fragment{
		ObjectID:   0,
		FragmentID: 0,
		Start:      true,
		End:        true,
		Data:       msgBytes,
	}

	fragBytes, err := frag.Encode()
	if err != nil {
		t.Fatalf("Fragment.Encode failed: %v", err)
	}
	_, err = transport.Write(fragBytes)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read the response
	buf := make([]byte, 4096)
	n, err := transport.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n == 0 {
		t.Error("Expected non-empty response")
	}

	// Decode the response fragment
	respFrag, err := fragments.Decode(buf[:n])
	if err != nil {
		t.Fatalf("Decode fragment failed: %v", err)
	}

	// Decode the response message
	respMsg, err := messages.Decode(respFrag.Data)
	if err != nil {
		t.Fatalf("Decode message failed: %v", err)
	}

	// Verify it's a SESSION_CAPABILITY response
	if respMsg.Type != messages.MessageTypeSessionCapability {
		t.Errorf("Response type = %v, want SESSION_CAPABILITY", respMsg.Type)
	}

	if respMsg.Destination != messages.DestinationClient {
		t.Errorf("Response destination = %v, want DestinationClient", respMsg.Destination)
	}
}

// TestPSRPCore_PipelineExecution tests pipeline creation and execution.
func TestPSRPCore_PipelineExecution(t *testing.T) {
	poolID := uuid.New()
	transport := NewMockPSRPTransport(poolID)

	pool := runspace.New(transport, poolID)

	ctx := context.Background()

	err := pool.Open(ctx)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer pool.Close(ctx)

	// Create a pipeline
	pl, err := pool.CreatePipeline("Write-Output 'Hello'")
	if err != nil {
		t.Fatalf("CreatePipeline failed: %v", err)
	}

	if pl == nil {
		t.Fatal("pipeline is nil")
	}

	t.Logf("Pipeline created with ID: %v", pl.ID())
}
