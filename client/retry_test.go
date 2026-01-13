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
	policy := &RetryPolicy{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
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

	// Test with explicit defaults
	policy := DefaultRetryPolicy()
	got = calculateRetryBackoff(1, policy)
	if got != 100*time.Millisecond {
		t.Errorf("calculateRetryBackoff(1) = %v, want 100ms", got)
	}
}
