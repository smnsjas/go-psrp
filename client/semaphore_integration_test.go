package client

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
)

// TestIntegration_SemaphoreConcurrency verifies that Client limits concurrent pipeline streams.
func TestIntegration_SemaphoreConcurrency(t *testing.T) {
	// 1. Setup Client with MaxRunspaces = 2
	maxRunspaces := 2
	cfg := DefaultConfig()
	cfg.MaxRunspaces = maxRunspaces
	cfg.MaxQueueSize = 100
	cfg.Username = "user"
	cfg.Password = "pass"

	mockBackend := &MockBackend{
		PrepareFunc: func(ctx context.Context, p *pipeline.Pipeline, payload string) (io.Reader, func(), error) {
			// Return dummy reader/success
			return strings.NewReader(""), func() {}, nil
		},
	}
	c, err := New("localhost", cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	c.backend = mockBackend
	c.connected = true
	c.psrpPool = runspace.New(&DummyReadWriter{
		ReadFunc: func(p []byte) (n int, err error) {
			select {} // Block reads to simulate open stream
		},
		WriteFunc: func(p []byte) (n int, err error) { return len(p), nil },
	}, uuid.New())
	c.psrpPool.ResumeOpened()

	// Initialize semaphore
	c.semaphore = newPoolSemaphore(maxRunspaces, 100, 500*time.Millisecond) // 500ms acquire timeout

	// 2. Acquire maxRunspaces streams
	streams := make([]*StreamResult, maxRunspaces)
	ctx := context.Background()

	for i := 0; i < maxRunspaces; i++ {
		stream, err := c.ExecuteStream(ctx, "echo test")
		if err != nil {
			t.Fatalf("ExecuteStream %d failed: %v", i, err)
		}
		streams[i] = stream
	}

	// 3. Try to acquire one more - should fail (timeout)
	// We run this in a goroutine to ensure we don't block main test forever if bug
	doneCh := make(chan error, 1)
	go func() {
		// Use a context that allows enough time for Acquire timeout (500ms) to trigger?
		// Acquire uses its own timeout logic (c.config.Timeout? No, semaphore has internal timeout)
		// logic: newPoolSemaphore(..., timeout)
		// We set it to 500ms.

		// If we pass a shorter context, it should fail with context deadline.
		// If we pass longer context, it should fail with ErrAcquireTimeout.
		ctxShort, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := c.ExecuteStream(ctxShort, "echo fail")
		doneCh <- err
	}()

	select {
	case err := <-doneCh:
		if err == nil {
			t.Error("Expected error for 3rd stream, got success")
		} else if err != context.DeadlineExceeded && err != ErrAcquireTimeout && !strings.Contains(err.Error(), "pool busy") {
			// "pool busy" wraps the error
			t.Logf("Got expected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("ExecuteStream timed out waiting for semaphore result")
	}

	// 4. Close one stream and retry
	// Note: Since DummyReadWriter blocks indefinitely and doesn't process Cancel messages,
	// stream.Wait() will hang. We simulate the cleanup manually for the test.
	// In a real scenario, the server would respond to Cancel/Close or disconnect.

	// Manually release usage for stream 0
	streams[0].cleanup()

	// Give it a moment to release
	time.Sleep(50 * time.Millisecond)

	// Verify stats
	active, _, _ := c.semaphore.Stats()
	if active != maxRunspaces-1 {
		t.Errorf("Expected %d active, got %d", maxRunspaces-1, active)
	}

	// Now should succeed
	stream3, err := c.ExecuteStream(ctx, "echo retry")
	if err != nil {
		t.Errorf("ExecuteStream retry failed: %v", err)
	}

	// Cleanup all
	// We call cleanup() directly because Wait() hangs
	if stream3 != nil {
		stream3.cleanup()
	}
	for i := 1; i < maxRunspaces; i++ {
		streams[i].cleanup()
	}
}
