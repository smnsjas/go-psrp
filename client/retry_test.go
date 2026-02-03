package client

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/smnsjas/go-psrpcore/runspace"
)

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "context cancelled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "EOF",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "ErrUnexpectedEOF",
			err:      io.ErrUnexpectedEOF,
			expected: true,
		},
		{
			name:     "RunspaceClosed",
			err:      runspace.ErrClosed,
			expected: false,
		},
		{
			name:     "RunspaceBroken",
			err:      runspace.ErrBroken,
			expected: false,
		},
		{
			name:     "Net I/O Timeout",
			err:      errors.New("read tcp 127.0.0.1:5985->127.0.0.1:54321: i/o timeout"),
			expected: true,
		},
		{
			name:     "Generic Error",
			err:      errors.New("something went wrong"),
			expected: false,
		},
		{
			name:     "Connection Reset",
			err:      errors.New("read: connection reset by peer"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryableError(tt.err); got != tt.expected {
				t.Errorf("isRetryableError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCalculateRetryBackoff(t *testing.T) {
	// No jitter for predictable testing
	policy := &RetryPolicy{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		Jitter:       0, // Disable jitter for exact testing
	}

	tests := []struct {
		name    string
		attempt int
		min     time.Duration
		max     time.Duration
	}{
		{
			name:    "Attempt 1",
			attempt: 1,
			min:     100 * time.Millisecond,
			max:     100 * time.Millisecond,
		},
		{
			name:    "Attempt 2",
			attempt: 2,
			min:     200 * time.Millisecond,
			max:     200 * time.Millisecond,
		},
		{
			name:    "Attempt 3",
			attempt: 3,
			min:     400 * time.Millisecond,
			max:     400 * time.Millisecond,
		},
		{
			name:    "Attempt 4",
			attempt: 4,
			min:     800 * time.Millisecond,
			max:     800 * time.Millisecond,
		},
		{
			name:    "Attempt 5 (Cap)",
			attempt: 5,
			min:     1 * time.Second,
			max:     1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateRetryBackoff(tt.attempt, policy)
			if got < tt.min || got > tt.max {
				t.Errorf("calculateRetryBackoff() = %v, want [%v, %v]", got, tt.min, tt.max)
			}
		})
	}
}

func TestCalculateRetryBackoff_Defaults(t *testing.T) {
	// Test with nil policy
	got := calculateRetryBackoff(1, nil)
	if got != time.Second {
		t.Errorf("calculateRetryBackoff(nil) = %v, want 1s", got)
	}

	// Test with explicit defaults (has 10% jitter, so accept range)
	policy := DefaultRetryPolicy()
	got = calculateRetryBackoff(1, policy)
	base := 100 * time.Millisecond
	minExpected := time.Duration(float64(base) * 0.9) // -10%
	maxExpected := time.Duration(float64(base) * 1.1) // +10%
	if got < minExpected || got > maxExpected {
		t.Errorf("calculateRetryBackoff(1) = %v, want [%v, %v]", got, minExpected, maxExpected)
	}
}

// TestCalculateRetryBackoff_Jitter verifies jitter produces variation.
func TestCalculateRetryBackoff_Jitter(t *testing.T) {
	policy := &RetryPolicy{
		InitialDelay: 1 * time.Second,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.2, // 20% jitter
	}

	// Run multiple iterations to verify jitter produces variation
	results := make(map[time.Duration]bool)
	for i := 0; i < 100; i++ {
		got := calculateRetryBackoff(1, policy)
		results[got] = true

		// Verify within expected range (±20%)
		base := 1 * time.Second
		minExpected := time.Duration(float64(base) * 0.8)
		maxExpected := time.Duration(float64(base) * 1.2)
		if got < minExpected || got > maxExpected {
			t.Errorf("calculateRetryBackoff() = %v, want [%v, %v]", got, minExpected, maxExpected)
		}
	}

	// Verify we got variation (at least 2 different values in 100 iterations)
	if len(results) < 2 {
		t.Errorf("Jitter should produce variation, got only %d unique values", len(results))
	}
}

// TestApplyJitter verifies jitter edge cases.
func TestApplyJitter(t *testing.T) {
	// Zero jitter should return exact value
	got := applyJitter(100*time.Millisecond, 0)
	if got != 100*time.Millisecond {
		t.Errorf("applyJitter(100ms, 0) = %v, want 100ms", got)
	}

	// Negative jitter should return exact value
	got = applyJitter(100*time.Millisecond, -0.1)
	if got != 100*time.Millisecond {
		t.Errorf("applyJitter(100ms, -0.1) = %v, want 100ms", got)
	}

	// Jitter > 1.0 should return exact value
	got = applyJitter(100*time.Millisecond, 1.5)
	if got != 100*time.Millisecond {
		t.Errorf("applyJitter(100ms, 1.5) = %v, want 100ms", got)
	}
}
