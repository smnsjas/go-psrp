package client

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

var (
	// ErrQueueFull is returned when the semaphore queue limit is reached.
	ErrQueueFull = errors.New("client: execution queue is full")

	// ErrAcquireTimeout is returned when waiting for a runspace slot times out.
	ErrAcquireTimeout = errors.New("client: timeout waiting for available runspace")
)

// poolSemaphore limits the number of concurrent executions to match MaxRunspaces.
// It prevents "thundering herd" issues by queuing requests client-side.
type poolSemaphore struct {
	sem       chan struct{} // channel acting as semaphore tokens
	maxSize   int
	queueSize int32 // atomic
	maxQueue  int
	timeout   time.Duration
}

// newPoolSemaphore creates a new semaphore with the given limits.
// maxRunspaces: Maximum number of concurrent executions.
// maxQueue: Maximum number of requests waiting for a slot (-1 = unbounded, 0 = no queue).
// timeout: Default timeout for Acquire.
func newPoolSemaphore(maxRunspaces, maxQueue int, timeout time.Duration) *poolSemaphore {
	if maxRunspaces < 1 {
		maxRunspaces = 1
	}
	return &poolSemaphore{
		sem:      make(chan struct{}, maxRunspaces),
		maxSize:  maxRunspaces,
		maxQueue: maxQueue,
		timeout:  timeout,
	}
}

// Acquire blocks until a runspace slot is available or timeout/cancel.
func (ps *poolSemaphore) Acquire(ctx context.Context) error {
	// Optimization: Try to acquire immediately without touching queue count
	// This ensures that if slots are open, we don't reject based on MaxQueueSize=0.
	select {
	case ps.sem <- struct{}{}:
		return nil
	default:
		// Must wait
	}

	// Increment queue counter (waiters)
	qLen := atomic.AddInt32(&ps.queueSize, 1)
	defer atomic.AddInt32(&ps.queueSize, -1)

	// Check queue limit
	// maxQueue < 0 means unbounded
	// maxQueue >= 0 means strict limit
	if ps.maxQueue >= 0 && int(qLen) > ps.maxQueue {
		return ErrQueueFull
	}

	// Determine timeout for this specific acquisition
	timeout := ps.timeout
	if timeout == 0 {
		timeout = 60 * time.Second // Default fallback
	}

	// Use a timer for the acquire timeout
	// Note: We don't defer timer.Stop() efficiently here if we exit early via semaphore,
	// but for simplicity it's acceptable. For high-perf, we might optimize.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case ps.sem <- struct{}{}:
		// Token acquired
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrAcquireTimeout
	}
}

// Release returns a runspace slot to the pool.
// It must only be called after a successful Acquire.
func (ps *poolSemaphore) Release() {
	select {
	case <-ps.sem:
		// Token released
	default:
		// This should not happen if Acquire/Release are paired correctly.
		// We could log a warning here if we had a logger reference.
	}
}

// Stats returns current pool utilization.
// active: Number of slots currently busy.
// queued: Number of requests waiting for a slot.
// max: Queue limit.
func (ps *poolSemaphore) Stats() (active, queued, max int) {
	return len(ps.sem), int(atomic.LoadInt32(&ps.queueSize)), ps.maxSize
}

// QueueLength returns the current number of waiters.
func (ps *poolSemaphore) QueueLength() int {
	return int(atomic.LoadInt32(&ps.queueSize))
}
