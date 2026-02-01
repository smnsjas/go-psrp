// Package client provides reconnection logic for PSRP connections.
package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// reconnectManager handles automatic reconnection with exponential backoff.
type reconnectManager struct {
	client *Client
	policy ReconnectPolicy

	mu        sync.Mutex
	running   bool
	stopCh    chan struct{}
	stoppedCh chan struct{}
}

// newReconnectManager creates a reconnect manager for the given client.
func newReconnectManager(c *Client, policy ReconnectPolicy) *reconnectManager {
	return &reconnectManager{
		client: c,
		policy: policy,
	}
}

// start begins the reconnection monitoring goroutine.
// It watches for disconnected/broken states and attempts reconnection.
func (rm *reconnectManager) start() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.running || !rm.policy.Enabled {
		return
	}

	rm.running = true
	rm.stopCh = make(chan struct{})
	rm.stoppedCh = make(chan struct{})

	go rm.loop()
}

// stop halts the reconnection manager.
func (rm *reconnectManager) stop() {
	rm.mu.Lock()
	if !rm.running {
		rm.mu.Unlock()
		return
	}
	close(rm.stopCh)
	stoppedCh := rm.stoppedCh
	rm.mu.Unlock()

	// Wait for loop to exit
	<-stoppedCh
}

// loop is the main reconnection monitoring loop.
func (rm *reconnectManager) loop() {
	defer func() {
		rm.mu.Lock()
		rm.running = false
		close(rm.stoppedCh)
		rm.mu.Unlock()
	}()

	// Poll interval for checking connection state
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-rm.stopCh:
			return
		case <-ticker.C:
			rm.checkAndReconnect()
		}
	}
}

// checkAndReconnect checks if reconnection is needed and attempts it.
func (rm *reconnectManager) checkAndReconnect() {
	health := rm.client.Health()

	// Only reconnect if unhealthy (Disconnected or Broken)
	if health != HealthUnhealthy {
		return
	}

	rm.client.logInfo("Reconnect: detected unhealthy state, attempting reconnection...")

	// Log reconnection attempt (NIST SP 800-92)
	rm.client.mu.Lock()
	if rm.client.securityLogger != nil {
		rm.client.securityLogger.LogReconnection(SubtypeReconnAttempt, OutcomeSuccess, SeverityInfo, map[string]any{
			"reason": "unhealthy_state",
		})
	}
	rm.client.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), rm.client.config.Timeout)
	defer cancel()

	err := rm.attemptReconnectWithBackoff(ctx)
	if err != nil {
		rm.client.logError("Reconnect: all attempts failed: %v", err)
		// Log exhausted (NIST SP 800-92)
		rm.client.mu.Lock()
		if rm.client.securityLogger != nil {
			rm.client.securityLogger.LogReconnection(SubtypeReconnExhausted, OutcomeFailure, SeverityError, map[string]any{
				"error": err.Error(),
			})
		}
		rm.client.mu.Unlock()
	} else {
		rm.client.logInfo("Reconnect: successfully reconnected")
		// Log success (NIST SP 800-92)
		rm.client.mu.Lock()
		if rm.client.securityLogger != nil {
			rm.client.securityLogger.LogReconnection(SubtypeReconnSuccess, OutcomeSuccess, SeverityInfo, nil)
		}
		rm.client.mu.Unlock()
	}
}

// attemptReconnectWithBackoff tries to reconnect with exponential backoff.
func (rm *reconnectManager) attemptReconnectWithBackoff(ctx context.Context) error {
	var lastErr error
	delay := rm.policy.InitialDelay

	for attempt := 1; rm.policy.MaxAttempts == 0 || attempt <= rm.policy.MaxAttempts; attempt++ {
		rm.client.logInfo("Reconnect: attempt %d/%d", attempt, rm.policy.MaxAttempts)

		// Check if we should stop
		select {
		case <-rm.stopCh:
			return context.Canceled
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Attempt reconnection
		err := rm.attemptReconnect(ctx)
		if err == nil {
			return nil // Success
		}

		lastErr = err
		rm.client.logWarn("Reconnect: attempt %d failed: %v", attempt, err)

		// Don't wait after the last attempt
		if rm.policy.MaxAttempts > 0 && attempt >= rm.policy.MaxAttempts {
			break
		}

		// Wait with backoff before next attempt
		waitDuration := rm.calculateBackoff(delay)
		select {
		case <-rm.stopCh:
			return context.Canceled
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDuration):
		}

		// Increase delay for next attempt (exponential backoff)
		delay = time.Duration(float64(delay) * 2)
		if delay > rm.policy.MaxDelay {
			delay = rm.policy.MaxDelay
		}
	}

	return lastErr
}

// attemptReconnect performs a single reconnection attempt.
func (rm *reconnectManager) attemptReconnect(ctx context.Context) error {
	c := rm.client

	c.mu.Lock()
	shellID := ""
	if c.backend != nil {
		shellID = c.backend.ShellID()
	}
	c.mu.Unlock()

	// Always use Reconnect, not Connect.
	// Connect() checks c.connected and returns nil if already connected,
	// but Reconnect() properly resets the pool even when c.connected is true.
	return c.Reconnect(ctx, shellID)
}

// calculateBackoff returns the delay with optional jitter.
func (rm *reconnectManager) calculateBackoff(baseDelay time.Duration) time.Duration {
	if rm.policy.Jitter <= 0 {
		return baseDelay
	}

	// Add jitter: delay * (1 + random(0, jitter))
	jitter := 0.0
	if value, err := cryptoRandFloat64(); err == nil {
		jitter = value
	}
	jitterFactor := 1.0 + (jitter * rm.policy.Jitter)
	return time.Duration(float64(baseDelay) * jitterFactor)
}

func cryptoRandFloat64() (float64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	value := binary.LittleEndian.Uint64(buf[:])
	return float64(value) / float64(^uint64(0)), nil
}

// isTransientError returns true if the error is likely transient and worth retrying.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Network errors, timeouts, and temporary failures are transient
	errStr := err.Error()

	transientPatterns := []string{
		"connection reset",
		"connection refused",
		"i/o timeout",
		"timeout",
		"temporary failure",
		"network is unreachable",
		"no route to host",
		"EOF",
	}

	for _, pattern := range transientPatterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}

	return false
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	sLower := make([]byte, len(s))
	substrLower := make([]byte, len(substr))

	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			sLower[i] = s[i] + 32
		} else {
			sLower[i] = s[i]
		}
	}

	for i := 0; i < len(substr); i++ {
		if substr[i] >= 'A' && substr[i] <= 'Z' {
			substrLower[i] = substr[i] + 32
		} else {
			substrLower[i] = substr[i]
		}
	}

	return len(s) >= len(substr) && bytesContains(sLower, substrLower)
}

// bytesContains checks if b contains sub.
func bytesContains(b, sub []byte) bool {
	for i := 0; i <= len(b)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Compile-time check that we use math package (for potential future use)
var _ = math.MaxFloat64
