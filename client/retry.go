package client

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"github.com/smnsjas/go-psrpcore/runspace"
)

// isRetryableError determines if an error should trigger command retry.
//
// Retryable errors are transient network/transport issues.
// Pool-level errors (ErrBroken) are NOT retryable here - they're handled
// by the reconnection flow.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Non-retryable: Pool permanently closed
	if errors.Is(err, runspace.ErrClosed) {
		return false
	}

	// Non-retryable: Pool broken (handled by reconnection flow)
	if errors.Is(err, runspace.ErrBroken) {
		return false
	}

	// Non-retryable: User cancelled
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Retryable: Network timeout
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Retryable: Connection closed/reset
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Fallback: String matching for stdlib network errors
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "broken pipe")
}

// calculateRetryBackoff computes exponential backoff with cap.
func calculateRetryBackoff(attempt int, policy *RetryPolicy) time.Duration {
	if policy == nil {
		return time.Second
	}

	delay := policy.InitialDelay
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}

	if attempt <= 1 {
		return delay
	}

	// Calculate exponential backoff: delay * (multiplier ^ (attempt - 1))
	multiplier := policy.Multiplier
	if multiplier < 1.0 {
		multiplier = 2.0
	}

	// Use float64 for calculation to avoid overflow before capping
	backoffFloat := float64(delay) * math.Pow(multiplier, float64(attempt-1))

	// Check for overflow or exceeding max duration
	if backoffFloat > float64(policy.MaxDelay) || backoffFloat > float64(math.MaxInt64) {
		backoff := policy.MaxDelay
		if backoff <= 0 {
			backoff = 5 * time.Second
		}
		return backoff
	}

	return time.Duration(backoffFloat)
}
