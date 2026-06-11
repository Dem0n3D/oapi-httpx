package metrics

import (
	"database/sql"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterDBPoolMetrics registers database/sql connection pool gauges.
func RegisterDBPoolMetrics(registerer prometheus.Registerer, db *sql.DB, commonLabels prometheus.Labels) error {
	if db == nil {
		return nil
	}
	for _, collector := range []prometheus.Collector{
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "db_pool_open_connections", Help: "Open database connections.", ConstLabels: commonLabels}, func() float64 { return float64(db.Stats().OpenConnections) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "db_pool_in_use_connections", Help: "Database connections currently in use.", ConstLabels: commonLabels}, func() float64 { return float64(db.Stats().InUse) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "db_pool_idle_connections", Help: "Idle database connections.", ConstLabels: commonLabels}, func() float64 { return float64(db.Stats().Idle) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "db_pool_wait_count_total", Help: "Total waits for database connections.", ConstLabels: commonLabels}, func() float64 { return float64(db.Stats().WaitCount) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "db_pool_wait_duration_seconds_total", Help: "Total wait duration for database connections in seconds.", ConstLabels: commonLabels}, func() float64 {
			return db.Stats().WaitDuration.Seconds()
		}),
	} {
		if err := registerer.Register(collector); err != nil {
			return err
		}
	}
	return nil
}
