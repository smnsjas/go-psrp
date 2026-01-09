package client

import (
	"testing"
	"time"
)

func TestDefaultReconnectPolicy(t *testing.T) {
	policy := DefaultReconnectPolicy()

	if policy.Enabled {
		t.Error("DefaultReconnectPolicy should have Enabled=false (opt-in)")
	}
	if policy.MaxAttempts != 5 {
		t.Errorf("Expected MaxAttempts=5, got %d", policy.MaxAttempts)
	}
	if policy.InitialDelay != 1*time.Second {
		t.Errorf("Expected InitialDelay=1s, got %v", policy.InitialDelay)
	}
	if policy.MaxDelay != 30*time.Second {
		t.Errorf("Expected MaxDelay=30s, got %v", policy.MaxDelay)
	}
	if policy.Jitter != 0.2 {
		t.Errorf("Expected Jitter=0.2, got %v", policy.Jitter)
	}
}

func TestReconnectManager_BackoffCalculation(t *testing.T) {
	policy := ReconnectPolicy{
		Enabled:      true,
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Jitter:       0.0, // No jitter for deterministic test
	}

	rm := newReconnectManager(nil, policy)

	// Test base delay calculation (no jitter)
	delay := rm.calculateBackoff(100 * time.Millisecond)
	if delay != 100*time.Millisecond {
		t.Errorf("Expected 100ms with no jitter, got %v", delay)
	}
}

func TestReconnectManager_BackoffWithJitter(t *testing.T) {
	policy := ReconnectPolicy{
		Enabled:      true,
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Jitter:       0.5, // 50% jitter
	}

	rm := newReconnectManager(nil, policy)

	// With 50% jitter, delay should be between 100ms and 150ms
	for i := 0; i < 10; i++ {
		delay := rm.calculateBackoff(100 * time.Millisecond)
		if delay < 100*time.Millisecond || delay > 150*time.Millisecond {
			t.Errorf("Delay %v outside expected range [100ms, 150ms]", delay)
		}
	}
}

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		errMsg    string
		transient bool
	}{
		{"connection reset by peer", true},
		{"connection refused", true},
		{"i/o timeout", true},
		{"timeout waiting for response", true},
		{"EOF", true},
		{"network is unreachable", true},
		{"no route to host", true},
		{"authentication failed", false},
		{"invalid credentials", false},
		{"permission denied", false},
		{"", false},
	}

	for _, tc := range tests {
		var err error
		if tc.errMsg != "" {
			err = &testError{msg: tc.errMsg}
		}

		result := isTransientError(err)
		if result != tc.transient {
			t.Errorf("isTransientError(%q) = %v, want %v", tc.errMsg, result, tc.transient)
		}
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"connection reset", "RESET", true},
		{"CONNECTION RESET", "reset", true},
		{"hello world", "WORLD", true},
		{"hello", "world", false},
		{"short", "very long substring", false},
		{"", "test", false},
		{"test", "", true},
	}

	for _, tc := range tests {
		got := containsIgnoreCase(tc.s, tc.substr)
		if got != tc.want {
			t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tc.s, tc.substr, got, tc.want)
		}
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
