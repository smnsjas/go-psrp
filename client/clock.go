package client

import (
	"sync"
	"time"
)

// Clock provides time operations (injectable for testing)
type Clock interface {
	Now() time.Time
}

// realClock implements Clock using actual system time
type realClock struct{}

// Now returns the current system time
func (realClock) Now() time.Time {
	return time.Now()
}

// mockClock implements Clock with manual time control (tests only)
type mockClock struct {
	mu      sync.Mutex
	current time.Time
}

// Now returns the mock current time
func (m *mockClock) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// Advance manually advances the mock clock by duration d
func (m *mockClock) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = m.current.Add(d)
}

// newMockClock creates a new mock clock starting at the given time
func newMockClock(start time.Time) *mockClock {
	return &mockClock{current: start}
}
