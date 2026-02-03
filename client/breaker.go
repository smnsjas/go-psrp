package client

import (
	"errors"
	"sync"
	"time"
)

// CircuitState represents the state of the circuit breaker.
type CircuitState int

const (
	// StateClosed means the circuit acts normally (requests pass).
	StateClosed CircuitState = iota
	// StateOpen means the circuit fails fast (requests blocked).
	StateOpen
	// StateHalfOpen means the circuit is probing (one request passes).
	StateHalfOpen
)

// String returns the string representation of the state.
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "Closed"
	case StateOpen:
		return "Open"
	case StateHalfOpen:
		return "Half-Open"
	default:
		return "Unknown"
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreaker implements the Circuit Breaker pattern.
type CircuitBreaker struct {
	mu sync.Mutex

	state       CircuitState
	failures    int
	lastFailure time.Time

	// Policy
	threshold int
	timeout   time.Duration
	enabled   bool
	clock     Clock

	// Event callbacks
	onStateChange func(from, to CircuitState)
	onOpen        func()
	onClose       func()
	onHalfOpen    func()
}

// NewCircuitBreaker creates a new circuit breaker with the given policy.
func NewCircuitBreaker(policy *CircuitBreakerPolicy) *CircuitBreaker {
	if policy == nil {
		return &CircuitBreaker{enabled: false, clock: realClock{}}
	}
	return &CircuitBreaker{
		state:         StateClosed,
		threshold:     policy.FailureThreshold,
		timeout:       policy.ResetTimeout,
		enabled:       policy.Enabled,
		clock:         realClock{},
		onStateChange: policy.OnStateChange,
		onOpen:        policy.OnOpen,
		onClose:       policy.OnClose,
		onHalfOpen:    policy.OnHalfOpen,
	}
}

// Execute runs the given function within the circuit breaker context.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if !cb.enabled {
		return fn()
	}

	if err := cb.checkState(); err != nil {
		return err
	}

	err := fn()

	cb.updateState(err)

	return err
}

// checkState determines if execution is allowed.
func (cb *CircuitBreaker) checkState() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateOpen {
		// Check if timeout has expired
		if cb.clock.Now().Sub(cb.lastFailure) > cb.timeout {
			cb.transitionToLocked(StateHalfOpen)
			return nil
		}
		return ErrCircuitOpen
	}

	// Used when Half-Open:
	// Only allow one concurrent request in Half-Open?
	// For simplicity, we allow it. If it fails, it goes back to Open.
	// We don't implement complex half-open limit here yet (simple approach).

	return nil
}

// transitionToLocked changes state and fires callbacks.
// Must be called with cb.mu held.
func (cb *CircuitBreaker) transitionToLocked(newState CircuitState) {
	if cb.state == newState {
		return
	}
	oldState := cb.state
	cb.state = newState

	// Fire callbacks asynchronously to prevent blocking
	if cb.onStateChange != nil {
		go cb.onStateChange(oldState, newState)
	}

	switch newState {
	case StateOpen:
		if cb.onOpen != nil {
			go cb.onOpen()
		}
	case StateClosed:
		if cb.onClose != nil {
			go cb.onClose()
		}
	case StateHalfOpen:
		if cb.onHalfOpen != nil {
			go cb.onHalfOpen()
		}
	}
}

// updateState updates the breaker state based on the result of the operation.
func (cb *CircuitBreaker) updateState(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		// Success
		if cb.state == StateHalfOpen {
			cb.transitionToLocked(StateClosed)
			cb.failures = 0
		} else if cb.state == StateClosed {
			cb.failures = 0
		}
		return
	}

	// Failure
	// Only count if it's NOT ErrCircuitOpen (which shouldn't happen here anyway)
	if err == ErrCircuitOpen {
		return
	}

	// Determine if error is failure-worthy?
	// Assuming almost any error from fn() counts as failure.
	// Ideally, we'd filter, but fn() here is Execute() which already filters transient errors via Retry?
	// Actually, if Retry fails, it returns error. That IS a failure.

	cb.failures++
	cb.lastFailure = cb.clock.Now()

	if cb.state == StateHalfOpen {
		cb.transitionToLocked(StateOpen)
		return
	}

	if cb.state == StateClosed && cb.failures >= cb.threshold {
		cb.transitionToLocked(StateOpen)
	}
}

// State returns the current state (thread-safe).
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}
