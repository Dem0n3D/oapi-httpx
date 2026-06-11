package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusOptions configures a Prometheus exporter with an isolated registry.
type PrometheusOptions struct {
	// CommonLabels are attached to every metric registered through the exporter.
	CommonLabels map[string]string

	// RegisterGo adds the standard Go runtime collector.
	RegisterGo bool

	// RegisterProcess adds the standard process collector.
	RegisterProcess bool
}

// PrometheusExporter owns a Prometheus registry and creates counters backed by
// prometheus/client_golang.
//
// The exporter intentionally uses a private registry so applications can expose
// only metrics they explicitly register.
type PrometheusExporter struct {
	registry     *prometheus.Registry
	commonLabels prometheus.Labels
}

// NewPrometheusExporter creates a Prometheus exporter and optionally registers
// standard Go/process collectors.
func NewPrometheusExporter(options PrometheusOptions) (*PrometheusExporter, error) {
	registry := prometheus.NewRegistry()
	exporter := &PrometheusExporter{
		registry:     registry,
		commonLabels: prometheus.Labels(copyLabels(options.CommonLabels)),
	}

	if options.RegisterGo {
		if err := registry.Register(collectors.NewGoCollector()); err != nil {
			return nil, fmt.Errorf("register go collector: %w", err)
		}
	}

	if options.RegisterProcess {
		if err := registry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
			return nil, fmt.Errorf("register process collector: %w", err)
		}
	}

	return exporter, nil
}

// Handler returns an HTTP handler that exposes the exporter's registry in
// Prometheus text format.
func (e *PrometheusExporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{})
}

// Registerer returns the exporter's registry as a prometheus.Registerer.
//
// Use this when wiring middleware that should publish into the same registry
// as business metrics.
func (e *PrometheusExporter) Registerer() prometheus.Registerer {
	return e.registry
}

// NewCounter registers a Prometheus counter vector.
//
// labelNames defines the dynamic labels expected at Add/Inc time. Missing label
// values are treated as empty strings by the returned Counter implementation.
func (e *PrometheusExporter) NewCounter(name string, help string, labelNames []string) (Counter, error) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        name,
		Help:        help,
		ConstLabels: e.commonLabels,
	}, labelNames)

	if err := e.registry.Register(counter); err != nil {
		return nil, fmt.Errorf("register prometheus counter %q: %w", name, err)
	}

	return prometheusCounter{
		counter:    counter,
		labelNames: append([]string(nil), labelNames...),
	}, nil
}

// NewDurationObserver registers a Prometheus histogram vector.
func (e *PrometheusExporter) NewDurationObserver(name string, help string, labelNames []string, buckets []float64) (DurationObserver, error) {
	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}
	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        name,
		Help:        help,
		ConstLabels: e.commonLabels,
		Buckets:     buckets,
	}, labelNames)

	if err := e.registry.Register(histogram); err != nil {
		return nil, fmt.Errorf("register prometheus histogram %q: %w", name, err)
	}

	return prometheusDurationObserver{
		histogram:  histogram,
		labelNames: append([]string(nil), labelNames...),
	}, nil
}

type prometheusCounter struct {
	counter    *prometheus.CounterVec
	labelNames []string
}

func (c prometheusCounter) Add(_ context.Context, labels map[string]string, value float64) error {
	if value < 0 {
		return fmt.Errorf("prometheus counter value must be non-negative")
	}

	values := make([]string, 0, len(c.labelNames))
	for _, name := range c.labelNames {
		values = append(values, labels[name])
	}
	c.counter.WithLabelValues(values...).Add(value)
	return nil
}

func (c prometheusCounter) Inc(ctx context.Context, labels map[string]string) error {
	return c.Add(ctx, labels, 1)
}

type prometheusDurationObserver struct {
	histogram  *prometheus.HistogramVec
	labelNames []string
}

func (o prometheusDurationObserver) Observe(_ context.Context, labels map[string]string, duration time.Duration) error {
	values := make([]string, 0, len(o.labelNames))
	for _, name := range o.labelNames {
		values = append(values, labels[name])
	}
	o.histogram.WithLabelValues(values...).Observe(duration.Seconds())
	return nil
}

func copyLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
