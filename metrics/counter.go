package metrics

import (
	"context"
	"errors"
)

type Counter interface {
	Add(ctx context.Context, labels map[string]string, value float64) error
	Inc(ctx context.Context, labels map[string]string) error
}

type CounterFunc func(ctx context.Context, labels map[string]string, value float64) error

func (f CounterFunc) Add(ctx context.Context, labels map[string]string, value float64) error {
	return f(ctx, labels, value)
}

func (f CounterFunc) Inc(ctx context.Context, labels map[string]string) error {
	return f(ctx, labels, 1)
}

type MultiCounter []Counter

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

func (c MultiCounter) Inc(ctx context.Context, labels map[string]string) error {
	return c.Add(ctx, labels, 1)
}

type NoopCounter struct{}

func (NoopCounter) Add(context.Context, map[string]string, float64) error {
	return nil
}

func (NoopCounter) Inc(context.Context, map[string]string) error {
	return nil
}
