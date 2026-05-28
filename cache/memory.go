package cache

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-process TTL cache implementation.
//
// Expired entries are removed lazily on reads. DeleteExpired may be called by
// service code if proactive cleanup is useful for a long-running process.
type MemoryStore[K comparable, V any] struct {
	mu      sync.RWMutex
	now     func() time.Time
	entries map[K]memoryEntry[V]
}

type memoryEntry[V any] struct {
	value     V
	expiresAt time.Time
}

// NewMemoryStore creates an empty in-memory store.
func NewMemoryStore[K comparable, V any]() *MemoryStore[K, V] {
	return &MemoryStore[K, V]{
		now:     time.Now,
		entries: make(map[K]memoryEntry[V]),
	}
}

func newMemoryStoreWithClock[K comparable, V any](now func() time.Time) *MemoryStore[K, V] {
	store := NewMemoryStore[K, V]()
	store.now = now
	return store
}

func (s *MemoryStore[K, V]) Get(ctx context.Context, key K) (V, bool, error) {
	if err := ctx.Err(); err != nil {
		var zero V
		return zero, false, err
	}

	now := s.now()

	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()
	if !ok {
		var zero V
		return zero, false, nil
	}

	if !entry.expiresAt.After(now) {
		s.mu.Lock()
		if current, ok := s.entries[key]; ok && !current.expiresAt.After(now) {
			delete(s.entries, key)
		}
		s.mu.Unlock()

		var zero V
		return zero, false, nil
	}

	return entry.value, true, nil
}

func (s *MemoryStore[K, V]) Set(ctx context.Context, key K, value V, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if ttl <= 0 {
		return s.Delete(ctx, key)
	}

	s.mu.Lock()
	s.entries[key] = memoryEntry[V]{
		value:     value,
		expiresAt: s.now().Add(ttl),
	}
	s.mu.Unlock()

	return nil
}

func (s *MemoryStore[K, V]) Delete(ctx context.Context, key K) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()

	return nil
}

// DeleteExpired removes all expired entries and returns the number of removed
// keys.
func (s *MemoryStore[K, V]) DeleteExpired() int {
	now := s.now()
	removed := 0

	s.mu.Lock()
	for key, entry := range s.entries {
		if !entry.expiresAt.After(now) {
			delete(s.entries, key)
			removed++
		}
	}
	s.mu.Unlock()

	return removed
}

// Len returns the number of currently stored entries, including entries that
// may have expired but have not been lazily removed yet.
func (s *MemoryStore[K, V]) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.entries)
}
