package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
)

type PrometheusHTTPOptions struct {
	Registerer   prometheus.Registerer
	CommonLabels prometheus.Labels
	Buckets      []float64
}

func PrometheusHTTP(options PrometheusHTTPOptions) func(http.Handler) http.Handler {
	registerer := options.Registerer
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	buckets := options.Buckets
	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}

	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "http_requests_total",
		Help:        "Total number of HTTP requests.",
		ConstLabels: options.CommonLabels,
	}, []string{"method", "route", "status"})
	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        "http_request_duration_seconds",
		Help:        "HTTP request duration in seconds.",
		ConstLabels: options.CommonLabels,
		Buckets:     buckets,
	}, []string{"method", "route", "status"})

	registerer.MustRegister(requestsTotal, requestDuration)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startedAt := time.Now()
			recorder := &statusRecorder{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			next.ServeHTTP(recorder, r)

			status := strconv.Itoa(recorder.status)
			route := routePattern(r)
			requestsTotal.WithLabelValues(r.Method, route, status).Inc()
			requestDuration.WithLabelValues(r.Method, route, status).Observe(time.Since(startedAt).Seconds())
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func routePattern(r *http.Request) string {
	if routeContext := chi.RouteContext(r.Context()); routeContext != nil {
		if pattern := strings.TrimSpace(routeContext.RoutePattern()); pattern != "" {
			return pattern
		}
	}

	return "unknown"
}
