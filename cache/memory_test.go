package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreSetGetDelete(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore[string, string]()

	if err := store.Set(ctx, "key", "value", time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	value, ok, err := store.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok || value != "value" {
		t.Fatalf("Get() = %q, %v; want value, true", value, ok)
	}

	if err := store.Delete(ctx, "key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, ok, err = store.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get() after Delete() error = %v", err)
	}
	if ok {
		t.Fatal("Get() after Delete() hit; want miss")
	}
}

func TestMemoryStoreExpiresEntries(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	store := newMemoryStoreWithClock[string, string](func() time.Time {
		return now
	})
	ctx := context.Background()

	if err := store.Set(ctx, "key", "value", time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	now = now.Add(time.Minute)
	value, ok, err := store.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok || value != "" {
		t.Fatalf("Get() = %q, %v; want zero, false", value, ok)
	}
	if store.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", store.Len())
	}
}

func TestMemoryStoreNonPositiveTTLDeletesEntry(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore[string, string]()

	if err := store.Set(ctx, "key", "value", time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := store.Set(ctx, "key", "updated", 0); err != nil {
		t.Fatalf("Set() with zero ttl error = %v", err)
	}

	_, ok, err := store.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok {
		t.Fatal("Set() with zero ttl kept value; want miss")
	}
}

func TestMemoryStoreDeleteExpired(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	store := newMemoryStoreWithClock[string, string](func() time.Time {
		return now
	})
	ctx := context.Background()

	if err := store.Set(ctx, "expired", "value", time.Minute); err != nil {
		t.Fatalf("Set(expired) error = %v", err)
	}
	if err := store.Set(ctx, "fresh", "value", 3*time.Minute); err != nil {
		t.Fatalf("Set(fresh) error = %v", err)
	}

	now = now.Add(2 * time.Minute)
	if removed := store.DeleteExpired(); removed != 1 {
		t.Fatalf("DeleteExpired() = %d, want 1", removed)
	}
	if store.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", store.Len())
	}
}

func TestMemoryStoreHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := NewMemoryStore[string, string]()

	if err := store.Set(ctx, "key", "value", time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("Set() error = %v, want context.Canceled", err)
	}

	_, _, err := store.Get(ctx, "key")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Get() error = %v, want context.Canceled", err)
	}

	if err := store.Delete(ctx, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() error = %v, want context.Canceled", err)
	}
}
