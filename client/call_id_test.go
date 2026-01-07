package client

import (
	"sync"
	"testing"
)

func TestCallIDManager_Atomic(t *testing.T) {
	m := newCallIDManager()

	// 1. Basic usage
	if id := m.Next(); id != 1 {
		t.Errorf("Next() = %d, want 1", id)
	}
	if id := m.Current(); id != 1 {
		t.Errorf("Current() = %d, want 1", id)
	}

	// 2. Set
	m.Set(100)
	if id := m.Current(); id != 100 {
		t.Errorf("Current() after Set = %d, want 100", id)
	}
	if id := m.Next(); id != 101 {
		t.Errorf("Next() after Set = %d, want 101", id)
	}

	// 3. Concurrency
	m.Set(0)
	concurrency := 100
	iterations := 1000
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.Next()
			}
		}()
	}
	wg.Wait()

	expected := int64(concurrency * iterations)
	if got := m.Current(); got != expected {
		t.Errorf("Concurrent increment failed: got %d, want %d", got, expected)
	}
}
