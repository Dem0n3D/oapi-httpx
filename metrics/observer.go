package metrics

import (
	"context"
	"errors"
	"time"
)

// DurationObserver records durations with a dynamic label set.
type DurationObserver interface {
	Observe(ctx context.Context, labels map[string]string, duration time.Duration) error
}

// DurationObserverFunc adapts a function to DurationObserver.
type DurationObserverFunc func(ctx context.Context, labels map[string]string, duration time.Duration) error

// Observe calls f with the provided labels and duration.
func (f DurationObserverFunc) Observe(ctx context.Context, labels map[string]string, duration time.Duration) error {
	return f(ctx, labels, duration)
}

// MultiDurationObserver fans out observations to multiple observers.
type MultiDurationObserver []DurationObserver

// Observe records the duration in every non-nil observer.
func (o MultiDurationObserver) Observe(ctx context.Context, labels map[string]string, duration time.Duration) error {
	var errs []error
	for _, observer := range o {
		if observer == nil {
			continue
		}
		if err := observer.Observe(ctx, labels, duration); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NoopDurationObserver discards all observations.
type NoopDurationObserver struct{}

// Observe discards the observation.
func (NoopDurationObserver) Observe(context.Context, map[string]string, time.Duration) error {
	return nil
}
