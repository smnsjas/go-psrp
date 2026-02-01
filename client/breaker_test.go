package client

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	// Create mock clock
	mc := newMockClock(time.Now())

	policy := &CircuitBreakerPolicy{
		Enabled:          true,
		FailureThreshold: 2,
		ResetTimeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreaker(policy)
	cb.clock = mc // Inject mock clock

	// 1. Initial State: Closed
	if state := cb.State(); state != StateClosed {
		t.Errorf("Initial state = %v, want Closed", state)
	}

	// 2. Success doesn't change state
	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Errorf("Execute(success) error = %v", err)
	}
	if state := cb.State(); state != StateClosed {
		t.Errorf("After success state = %v, want Closed", state)
	}

	// 3. Failure 1 (Threshold 2)
	dummyErr := errors.New("dummy")
	err = cb.Execute(func() error { return dummyErr })
	if err != dummyErr {
		t.Errorf("Execute(fail) error = %v, want dummyErr", err)
	}
	if state := cb.State(); state != StateClosed {
		t.Errorf("After 1 failure state = %v, want Closed", state)
	}

	// 4. Failure 2 (Threshold reached)
	_ = cb.Execute(func() error { return dummyErr })
	if state := cb.State(); state != StateOpen {
		t.Errorf("After 2 failures state = %v, want Open", state)
	}

	// 5. Fail Fast (Open)
	err = cb.Execute(func() error { return nil }) // Should not execute
	if err != ErrCircuitOpen {
		t.Errorf("Execute(Open) error = %v, want ErrCircuitOpen", err)
	}

	// 6. Advance time past timeout -> Half-Open
	mc.Advance(150 * time.Millisecond)
	// First call transitions to Half-Open and executes
	ran := false
	err = cb.Execute(func() error {
		ran = true
		return nil // Success
	})
	if !ran {
		t.Error("Execute(Half-Open) did not run function")
	}
	if err != nil {
		t.Errorf("Execute(Half-Open) error = %v", err)
	}

	// 7. Success in Half-Open -> Closed
	if state := cb.State(); state != StateClosed {
		t.Errorf("After recovery state = %v, want Closed", state)
	}
}

func TestCircuitBreaker_HalfOpenFailure(t *testing.T) {
	// Create mock clock
	mc := newMockClock(time.Now())

	policy := &CircuitBreakerPolicy{
		Enabled:          true,
		FailureThreshold: 1,
		ResetTimeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreaker(policy)
	cb.clock = mc // Inject mock clock

	// 1. Trip breaker
	cb.Execute(func() error { return errors.New("fail") })
	if cb.State() != StateOpen {
		t.Fatalf("Failed to open breaker")
	}

	// 2. Advance time past timeout
	mc.Advance(150 * time.Millisecond)

	// 3. Fail in Half-Open
	ran := false
	err := cb.Execute(func() error {
		ran = true
		return errors.New("fail again")
	})
	if !ran {
		t.Error("Did not run probe")
	}
	if err == nil {
		t.Error("Expected error")
	}

	// 4. Back to Open
	if state := cb.State(); state != StateOpen {
		t.Errorf("After failed probe state = %v, want Open", state)
	}

	// 5. Fail Fast again
	err = cb.Execute(func() error { return nil })
	if err != ErrCircuitOpen {
		t.Errorf("Expected ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_Disabled(t *testing.T) {
	policy := &CircuitBreakerPolicy{Enabled: false}
	cb := NewCircuitBreaker(policy)

	// Should never open
	for i := 0; i < 10; i++ {
		cb.Execute(func() error { return errors.New("fail") })
	}
	if cb.State() != StateClosed {
		t.Errorf("Disabled breaker opened")
	}
}

func TestCircuitBreaker_Concurrency(t *testing.T) {
	policy := &CircuitBreakerPolicy{
		Enabled:          true,
		FailureThreshold: 100,
		ResetTimeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreaker(policy)

	var wg sync.WaitGroup
	// Run parallel successes and failures
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cb.Execute(func() error { return nil })
			cb.Execute(func() error { return errors.New("fail") })
		}()
	}
	wg.Wait()
}
