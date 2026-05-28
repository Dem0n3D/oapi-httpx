package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGetOrLoadReturnsCachedValue(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore[string, int]()
	if err := store.Set(ctx, "answer", 42, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	called := false
	value, err := GetOrLoad(ctx, store, "answer", time.Minute, func(context.Context) (int, error) {
		called = true
		return 0, nil
	})
	if err != nil {
		t.Fatalf("GetOrLoad() error = %v", err)
	}
	if value != 42 {
		t.Fatalf("GetOrLoad() value = %d, want 42", value)
	}
	if called {
		t.Fatal("loader was called on cache hit")
	}
}

func TestGetOrLoadStoresLoadedValue(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore[string, int]()

	value, err := GetOrLoad(ctx, store, "answer", time.Minute, func(context.Context) (int, error) {
		return 42, nil
	})
	if err != nil {
		t.Fatalf("GetOrLoad() error = %v", err)
	}
	if value != 42 {
		t.Fatalf("GetOrLoad() value = %d, want 42", value)
	}

	cached, ok, err := store.Get(ctx, "answer")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok || cached != 42 {
		t.Fatalf("Get() = %d, %v; want 42, true", cached, ok)
	}
}

func TestGetOrLoadDoesNotStoreOnLoadError(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore[string, int]()
	loadErr := errors.New("load failed")

	_, err := GetOrLoad(ctx, store, "answer", time.Minute, func(context.Context) (int, error) {
		return 0, loadErr
	})
	if !errors.Is(err, loadErr) {
		t.Fatalf("GetOrLoad() error = %v, want %v", err, loadErr)
	}

	_, ok, err := store.Get(ctx, "answer")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok {
		t.Fatal("value was cached after loader error")
	}
}

func TestNoopStoreAlwaysMisses(t *testing.T) {
	ctx := context.Background()
	store := NoopStore[string, int]{}

	if err := store.Set(ctx, "answer", 42, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	value, ok, err := store.Get(ctx, "answer")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok || value != 0 {
		t.Fatalf("Get() = %d, %v; want zero, false", value, ok)
	}
}
