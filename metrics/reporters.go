package metrics

import (
	"context"
	"time"
)

const (
	IntegrationRequestsMetricName        = "integration_requests_total"
	IntegrationRequestDurationMetricName = "integration_request_duration_seconds"
)

// IntegrationReporter records external integration request counts and latency.
type IntegrationReporter struct {
	requests Counter
	duration DurationObserver
}

// NewIntegrationReporter creates an integration reporter from generic metric primitives.
func NewIntegrationReporter(requests Counter, duration DurationObserver) *IntegrationReporter {
	if requests == nil {
		requests = NoopCounter{}
	}
	if duration == nil {
		duration = NoopDurationObserver{}
	}
	return &IntegrationReporter{
		requests: requests,
		duration: duration,
	}
}

// Observe records one integration request.
func (r *IntegrationReporter) Observe(integration string, operation string, status string, duration time.Duration) {
	if r == nil {
		return
	}
	ctx := context.Background()
	labels := map[string]string{
		"integration": integration,
		"operation":   operation,
		"status":      status,
	}
	_ = r.requests.Inc(ctx, labels)
	_ = r.duration.Observe(ctx, labels, duration)
}

// NewPrometheusIntegrationReporter registers the standard integration metrics.
func (e *PrometheusExporter) NewIntegrationReporter() (*IntegrationReporter, error) {
	requests, err := e.NewCounter(
		IntegrationRequestsMetricName,
		"Total external integration requests.",
		[]string{"integration", "operation", "status"},
	)
	if err != nil {
		return nil, err
	}
	duration, err := e.NewDurationObserver(
		IntegrationRequestDurationMetricName,
		"External integration request duration in seconds.",
		[]string{"integration", "operation", "status"},
		nil,
	)
	if err != nil {
		return nil, err
	}
	return NewIntegrationReporter(requests, duration), nil
}

// LabeledCounter provides convenience methods for counters updated with an
// ordered set of label values.
type LabeledCounter struct {
	counter    Counter
	labelNames []string
}

// NewLabeledCounter wraps a generic counter.
func NewLabeledCounter(counter Counter, labelNames []string) *LabeledCounter {
	if counter == nil {
		counter = NoopCounter{}
	}
	return &LabeledCounter{
		counter:    counter,
		labelNames: append([]string(nil), labelNames...),
	}
}

// NewLabeledCounter registers and wraps a Prometheus counter.
func (e *PrometheusExporter) NewLabeledCounter(name string, help string, labelNames []string) (*LabeledCounter, error) {
	counter, err := e.NewCounter(name, help, labelNames)
	if err != nil {
		return nil, err
	}
	return NewLabeledCounter(counter, labelNames), nil
}

// Add increases the counter with label values in the configured order.
func (c *LabeledCounter) Add(value float64, labelValues ...string) {
	if c == nil {
		return
	}
	labels := make(map[string]string, len(c.labelNames))
	for i, name := range c.labelNames {
		if i < len(labelValues) {
			labels[name] = labelValues[i]
		}
	}
	_ = c.counter.Add(context.Background(), labels, value)
}

// Inc increases the counter by one with label values in the configured order.
func (c *LabeledCounter) Inc(labelValues ...string) {
	c.Add(1, labelValues...)
}
