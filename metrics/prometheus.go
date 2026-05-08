package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusOptions struct {
	CommonLabels    map[string]string
	RegisterGo      bool
	RegisterProcess bool
}

type PrometheusExporter struct {
	registry     *prometheus.Registry
	commonLabels prometheus.Labels
}

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

func (e *PrometheusExporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{})
}

func (e *PrometheusExporter) Registerer() prometheus.Registerer {
	return e.registry
}

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

func copyLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
