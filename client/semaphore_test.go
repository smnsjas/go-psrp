package client

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestPoolSemaphore_AcquireRelease(t *testing.T) {
	// Create a semaphore with capacity 2, unbounded queue
	sem := newPoolSemaphore(2, -1, time.Second)

	ctx := context.Background()

	// Acquire 1
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("First Acquire failed: %v", err)
	}
	active, _, _ := sem.Stats()
	if active != 1 {
		t.Errorf("Expected 1 active, got %d", active)
	}

	// Acquire 2
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("Second Acquire failed: %v", err)
	}
	active, _, _ = sem.Stats()
	if active != 2 {
		t.Errorf("Expected 2 active, got %d", active)
	}

	// Release 1
	sem.Release()
	active, _, _ = sem.Stats()
	if active != 1 {
		t.Errorf("Expected 1 active after release, got %d", active)
	}

	// Release 2
	sem.Release()
	active, _, _ = sem.Stats()
	if active != 0 {
		t.Errorf("Expected 0 active after release, got %d", active)
	}
}

func TestPoolSemaphore_QueueLimit(t *testing.T) {
	// Capacity 1, Queue Limit 1
	sem := newPoolSemaphore(1, 1, time.Second)
	ctx := context.Background()

	// Fill capacity
	sem.Acquire(ctx)

	// Fill queue (1 waiter)
	released := make(chan struct{})
	go func() {
		defer close(released)
		sem.Acquire(ctx) // This should block and count as queued
	}()

	// Give goroutine time to enter Acquire and increment queue count
	time.Sleep(50 * time.Millisecond)

	_, queued, _ := sem.Stats()
	if queued != 1 {
		t.Errorf("Expected 1 queued, got %d", queued)
	}

	// Try to acquire again - should fail immediately due to max queue
	err := sem.Acquire(ctx)
	if err != ErrQueueFull {
		t.Errorf("Expected ErrQueueFull, got %v", err)
	}

	// Clean up
	sem.Release() // Release main capacity
	<-released    // Waiter acquires
	sem.Release() // Waiter releases (defer not in queued func but assumed)
}

func TestPoolSemaphore_Timeout(t *testing.T) {
	// Capacity 1
	sem := newPoolSemaphore(1, -1, 50*time.Millisecond) // Short timeout
	ctx := context.Background()

	// Fill capacity (Acquire returns nil)
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Try acquire again - should timeout
	start := time.Now()
	err := sem.Acquire(ctx)
	elapsed := time.Since(start)

	if err != ErrAcquireTimeout {
		t.Errorf("Expected ErrAcquireTimeout, got %v", err)
	}

	if elapsed < 50*time.Millisecond {
		t.Errorf("Timeout returned too early: %v", elapsed)
	}
}

func TestPoolSemaphore_ContextCancel(t *testing.T) {
	sem := newPoolSemaphore(1, -1, time.Second)
	ctx, cancel := context.WithCancel(context.Background())

	sem.Acquire(ctx) // Fill

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := sem.Acquire(ctx) // Should block then cancel
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}

func TestPoolSemaphore_Concurrency(t *testing.T) {
	// Verify that we never exceed capacity
	maxRunspaces := 5
	sem := newPoolSemaphore(maxRunspaces, -1, 5*time.Second)
	ctx := context.Background()

	concurrencyCount := int32(0)
	maxObserved := int32(0)
	var mu sync.Mutex

	var wg sync.WaitGroup
	params := 50 // 50 goroutines trying to enter 5 slots

	for i := 0; i < params; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sem.Acquire(ctx); err != nil {
				t.Errorf("Acquire failed: %v", err)
				return
			}
			defer sem.Release()

			// Check concurrency
			mu.Lock()
			concurrencyCount++
			if concurrencyCount > maxObserved {
				maxObserved = concurrencyCount
			}
			if concurrencyCount > int32(maxRunspaces) {
				t.Errorf("Exceeded max capacity! %d > %d", concurrencyCount, maxRunspaces)
			}
			mu.Unlock()

			// Simulate work
			time.Sleep(10 * time.Millisecond)

			mu.Lock()
			concurrencyCount--
			mu.Unlock()
		}()
	}

	wg.Wait()

	if maxObserved > int32(maxRunspaces) {
		t.Errorf("Max observed concurrency %d exceeded limit %d", maxObserved, maxRunspaces)
	}
}

func TestPoolSemaphore_ZeroQueue(t *testing.T) {
	// Capacity 1, Queue 0 (Strictly no queuing)
	sem := newPoolSemaphore(1, 0, time.Second)
	ctx := context.Background()

	// Fill capacity
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Try to acquire again - should fail immediately with ErrQueueFull
	// because queue is 0, so even entrance into queue is denied if it's full?
	// Logic: `int(qLen) > (ps.maxSize + ps.maxQueue)`
	// qLen (when 2nd acquires) = 2.
	// maxSize=1, maxQueue=0. -> 1+0=1.
	// 2 > 1 -> True. Returns ErrQueueFull. Correct.

	err := sem.Acquire(ctx)
	if err != ErrQueueFull {
		t.Errorf("Expected ErrQueueFull, got %v", err)
	}
}
