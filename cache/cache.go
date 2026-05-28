package cache

import (
	"context"
	"time"
)

// Store is a backend-neutral cache interface.
//
// Values returned by implementations should be treated as immutable by callers.
// Implementations are not required to deep-copy values.
type Store[K comparable, V any] interface {
	// Get returns the cached value for key.
	Get(ctx context.Context, key K) (V, bool, error)

	// Set stores value for key until ttl expires.
	// Non-positive ttl values disable caching for the key and should remove any
	// existing value.
	Set(ctx context.Context, key K, value V, ttl time.Duration) error

	// Delete removes key from the cache.
	Delete(ctx context.Context, key K) error
}

// Loader loads a value for a cache miss.
type Loader[V any] func(context.Context) (V, error)

// GetOrLoad returns a cached value or loads and stores it on miss.
func GetOrLoad[K comparable, V any](
	ctx context.Context,
	store Store[K, V],
	key K,
	ttl time.Duration,
	load Loader[V],
) (V, error) {
	if store != nil {
		value, ok, err := store.Get(ctx, key)
		if err != nil {
			var zero V
			return zero, err
		}
		if ok {
			return value, nil
		}
	}

	value, err := load(ctx)
	if err != nil {
		var zero V
		return zero, err
	}

	if store != nil {
		if err := store.Set(ctx, key, value, ttl); err != nil {
			var zero V
			return zero, err
		}
	}

	return value, nil
}

// NoopStore discards all writes and always misses.
type NoopStore[K comparable, V any] struct{}

func (NoopStore[K, V]) Get(context.Context, K) (V, bool, error) {
	var zero V
	return zero, false, nil
}

func (NoopStore[K, V]) Set(context.Context, K, V, time.Duration) error {
	return nil
}

func (NoopStore[K, V]) Delete(context.Context, K) error {
	return nil
}
