package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var requestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "rexec_requests_total",
		Help: "Total number of HTTP requests handled by rexec-server.",
	},
	[]string{"handler", "status_code"},
)

var requestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "rexec_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"handler"},
)

var activeSessions = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "rexec_active_sessions",
		Help: "Current number of active rexec sessions.",
	},
	[]string{"type"},
)

var webhookDecisionsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "rexec_webhook_decisions_total",
		Help: "Total number of webhook allow and deny decisions.",
	},
	[]string{"decision"},
)

var errorsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "rexec_errors_total",
		Help: "Total number of internal errors by component.",
	},
	[]string{"component"},
)

var auditCommandsTotal = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "rexec_audit_commands_total",
		Help: "Total number of audit command events logged.",
	},
)

var auditKeystrokesTotal = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "rexec_audit_keystrokes_total",
		Help: "Total number of keystrokes received by the async auditor.",
	},
)

func init() {
	prometheus.MustRegister(
		requestsTotal,
		requestDuration,
		activeSessions,
		webhookDecisionsTotal,
		errorsTotal,
		auditCommandsTotal,
		auditKeystrokesTotal,
	)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

func (r *statusRecorder) Flush() {
	if fl, ok := r.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func instrumentHandler(handlerName string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()

		next(rec, r)

		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		requestsTotal.WithLabelValues(handlerName, strconv.Itoa(rec.status)).Inc()
		requestDuration.WithLabelValues(handlerName).Observe(time.Since(start).Seconds())
	}
}

func recordError(component string) {
	errorsTotal.WithLabelValues(component).Inc()
}

func MetricsHandler() http.Handler {
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	return metricsMux
}

func buildMetricsServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func StartMetricsServer() {
	if MetricsPort <= 0 {
		SysLogger.Info().Int("metrics_port", MetricsPort).Msg("metrics endpoint disabled")
		return
	}

	addr := fmt.Sprintf(":%d", MetricsPort)
	srv := buildMetricsServer(addr)
	SysLogger.Info().Int("metrics_port", MetricsPort).Msg("starting prometheus metrics endpoint")
	if err := srv.ListenAndServe(); err != nil {
		SysLogger.Fatal().Err(err).Msg("failed to start metrics endpoint")
	}
}
