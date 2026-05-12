package metrics

import (
	"context"
	"errors"
)

// Counter is a backend-neutral monotonically increasing metric.
//
// Implementations may export the value to pull-based systems such as
// Prometheus or push-based systems such as Yandex Monitoring. Labels are
// intentionally passed per call so domain packages can keep metric semantics
// close to the business event being reported.
type Counter interface {
	// Add increases the counter by value for the given label set.
	// Implementations should reject negative values.
	Add(ctx context.Context, labels map[string]string, value float64) error

	// Inc increases the counter by one for the given label set.
	Inc(ctx context.Context, labels map[string]string) error
}

// CounterFunc adapts a function to Counter.
type CounterFunc func(ctx context.Context, labels map[string]string, value float64) error

// Add calls f with the provided labels and value.
func (f CounterFunc) Add(ctx context.Context, labels map[string]string, value float64) error {
	return f(ctx, labels, value)
}

// Inc calls f with value 1.
func (f CounterFunc) Inc(ctx context.Context, labels map[string]string) error {
	return f(ctx, labels, 1)
}

// MultiCounter fans out counter updates to multiple counters.
//
// This is useful during metric backend migrations or when explicitly writing
// the same business event to more than one exporter. It should be an opt-in
// choice at service wiring time, not an implicit default.
type MultiCounter []Counter

// Add increases every non-nil counter and returns a joined error if any update
// fails. All counters are attempted even when earlier counters fail.
func (c MultiCounter) Add(ctx context.Context, labels map[string]string, value float64) error {
	var errs []error
	for _, counter := range c {
		if counter == nil {
			continue
		}
		if err := counter.Add(ctx, labels, value); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Inc increases every non-nil counter by one.
func (c MultiCounter) Inc(ctx context.Context, labels map[string]string) error {
	return c.Add(ctx, labels, 1)
}

// NoopCounter discards all updates.
//
// It is intended for disabled metrics providers and tests that do not care
// about metric side effects.
type NoopCounter struct{}

// Add discards the update.
func (NoopCounter) Add(context.Context, map[string]string, float64) error {
	return nil
}

// Inc discards the update.
func (NoopCounter) Inc(context.Context, map[string]string) error {
	return nil
}
