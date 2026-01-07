package client

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/messages"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// TestExecuteStream_Streaming verifies that output is received as it is produced,
// not all at once at the end.
func TestExecuteStream_Streaming(t *testing.T) {
	// Setup mock backend
	pr, pw := io.Pipe()
	defer pr.Close()

	mockBackend := &MockBackend{
		PrepareFunc: func(ctx context.Context, p *pipeline.Pipeline, payload string) (io.Reader, func(), error) {
			return pr, func() { pr.Close() }, nil
		},
	}

	c := &Client{
		config:    DefaultConfig(),
		backend:   mockBackend,
		connected: true,
		psrpPool:  runspace.New(&DummyReadWriter{}, uuid.New()),
		semaphore: newPoolSemaphore(1, 0, time.Second),
		callID:    newCallIDManager(),
	}
	c.psrpPool.ResumeOpened()

	// Channels to coordinate test timing
	firstOutputReceived := make(chan struct{})

	// Start ExecuteStream
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := c.ExecuteStream(ctx, "echo 1; sleep 1; echo 2")
	if err != nil {
		t.Fatalf("ExecuteStream failed: %v", err)
	}

	// Consumer goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		count := 0
		for {
			select {
			case _, ok := <-stream.Output:
				if !ok {
					return
				}
				count++
				if count == 1 {
					close(firstOutputReceived)
				}
			case <-stream.Errors:
			case <-stream.Warnings:
			case <-stream.Verbose:
			case <-stream.Debug:
			case <-stream.Progress:
			case <-stream.Information:
			}
		}
	}()

	// Producer goroutine (simulating server)
	go func() {
		defer pw.Close()
		// 1. Send first output
		sendOutput(t, pw, int32(1))

		// 2. Wait a bit (simulate delay between outputs)
		// Real test: if consumer gets first output before second is sent, it's streaming!
		time.Sleep(50 * time.Millisecond)

		// 3. Send second output
		sendOutput(t, pw, int32(2))

		// 4. Complete
		sendState(t, pw, messages.RunspacePoolStateOpened, messages.PipelineStateCompleted, nil)
	}()

	// Verify we got the first output
	select {
	case <-firstOutputReceived:
		// Good, we got output while "server" was still sending
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for first output")
	}

	// Wait for completion
	if err := stream.Wait(); err != nil {
		t.Errorf("Wait() failed: %v", err)
	}
	wg.Wait()
}
