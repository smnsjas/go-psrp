package client

import (
	"sync/atomic"
)

// callIDManager manages atomic generation of PSRP message IDs.
// PSRP requires sequential, unique IDs for request tracking.
type callIDManager struct {
	id atomic.Int64
}

// newCallIDManager creates a new manager with the initial ID set to 0.
func newCallIDManager() *callIDManager {
	return &callIDManager{}
}

// Next increments and returns the next ID.
// This is thread-safe.
func (m *callIDManager) Next() int64 {
	return m.id.Add(1)
}

// Current returns the current ID without incrementing.
func (m *callIDManager) Current() int64 {
	return m.id.Load()
}

// Set sets the current ID explicitly (e.g., during state restoration).
// It acts as a memory fence ensuring subsequent Load/Add see this value.
func (m *callIDManager) Set(val int64) {
	m.id.Store(val)
}
