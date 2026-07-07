package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

type mockHijacker struct {
	http.ResponseWriter
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.rw, nil
}

type mockFlusher struct {
	http.ResponseWriter
	flushed bool
}

func (m *mockFlusher) Flush() {
	m.flushed = true
}

func TestInstrumentHandlerRecordsRequestMetrics(t *testing.T) {
	requestsTotal.Reset()

	handler := instrumentHandler("test-handler", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler(rr, req)

	if got := testutil.ToFloat64(requestsTotal.WithLabelValues("test-handler", "201")); got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}
}

func TestLogCommandIncrementsAuditCommandsMetric(t *testing.T) {
	before := testutil.ToFloat64(auditCommandsTotal)

	logCommand("ls -la", "alice", "session-1", "ns", "pod", "container", "10.0.0.1")

	after := testutil.ToFloat64(auditCommandsTotal)
	if after != before+1 {
		t.Fatalf("counter delta = %v, want 1", after-before)
	}
}

func TestStoreOrFlushIncrementsKeystrokesMetric(t *testing.T) {
	oldCommandMap := commandMap
	t.Cleanup(func() {
		commandMap = oldCommandMap
	})

	commandMap = map[string][]byte{}

	before := testutil.ToFloat64(auditKeystrokesTotal)

	storeOrFlush(asyncAudit{
		ctxid: "ctx-1",
		info: sessionInfo{
			User: "user",
		},
		ascii: []byte("abc"),
	})

	after := testutil.ToFloat64(auditKeystrokesTotal)
	if after != before+3 {
		t.Fatalf("counter delta = %v, want 3", after-before)
	}
}

func TestExecHandlerRecordsWebhookDecisionMetric(t *testing.T) {
	webhookDecisionsTotal.Reset()

	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = nil
	SecretSauce = "right-sauce"

	allowed := makeAdmissionReview("PodExecOptions", "alice", map[string][]string{
		"secret-sauce": {"right-sauce"},
	})
	denied := makeAdmissionReview("PodExecOptions", "alice", map[string][]string{
		"secret-sauce": {"wrong-sauce"},
	})

	postExecHandler(t, allowed, "application/json")
	postExecHandler(t, denied, "application/json")

	if got := testutil.ToFloat64(webhookDecisionsTotal.WithLabelValues("allowed")); got != 1 {
		t.Fatalf("allowed counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(webhookDecisionsTotal.WithLabelValues("denied")); got != 1 {
		t.Fatalf("denied counter = %v, want 1", got)
	}
}

func TestMetricsEndpointServesPrometheusOutput(t *testing.T) {
	requestsTotal.WithLabelValues("metrics-test", "200").Add(0)
	activeSessions.WithLabelValues("oneoff").Set(0)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	MetricsHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "rexec_requests_total") {
		t.Fatalf("expected metrics body to include rexec_requests_total")
	}
	if !strings.Contains(body, "rexec_active_sessions{type=\"oneoff\"}") {
		t.Fatalf("expected metrics body to include rexec_active_sessions")
	}
}

func TestStatusRecorderWriteSetsImplicit200(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}

	n, err := rec.Write([]byte("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 {
		t.Fatalf("wrote %d bytes, want 4", n)
	}
	if rec.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.status, http.StatusOK)
	}
}

func TestStatusRecorderHijackNotSupported(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}

	conn, rw, err := rec.Hijack()
	if err == nil {
		t.Fatal("expected error for non-hijacker ResponseWriter")
	}
	if conn != nil {
		t.Fatal("expected nil conn")
	}
	if rw != nil {
		t.Fatal("expected nil ReadWriter")
	}
}

func TestStatusRecorderHijackSupported(t *testing.T) {
	mockConn := &net.TCPConn{}
	r, w := io.Pipe()
	mockRW := bufio.NewReadWriter(bufio.NewReader(r), bufio.NewWriter(w))

	mockHJ := &mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           mockConn,
		rw:             mockRW,
	}
	rec := &statusRecorder{ResponseWriter: mockHJ}

	conn, rw, err := rec.Hijack()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn != mockConn {
		t.Fatal("expected hijack to return mocked conn")
	}
	if rw != mockRW {
		t.Fatal("expected hijack to return mocked ReadWriter")
	}
}

func TestStatusRecorderFlushNoFlusher(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}

	rec.Flush()
}

func TestStatusRecorderFlushCallsFlusher(t *testing.T) {
	mockF := &mockFlusher{
		ResponseWriter: httptest.NewRecorder(),
		flushed:        false,
	}
	rec := &statusRecorder{ResponseWriter: mockF}

	rec.Flush()
	if !mockF.flushed {
		t.Fatal("expected Flush to be called on underlying flusher")
	}
}

func TestInstrumentHandlerImplicitStatus200(t *testing.T) {
	requestsTotal.Reset()

	handler := instrumentHandler("implicit-handler", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("response")); err != nil {
			t.Fatalf("write response: %v", err)
		}
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler(rr, req)

	if got := testutil.ToFloat64(requestsTotal.WithLabelValues("implicit-handler", "200")); got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}
}

func TestStartMetricsServerDisabled(t *testing.T) {
	oldPort := MetricsPort
	t.Cleanup(func() {
		MetricsPort = oldPort
	})

	MetricsPort = 0

	done := make(chan struct{}, 1)
	go func() {
		StartMetricsServer()
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StartMetricsServer should return immediately when MetricsPort <= 0")
	}
}

func TestStartMetricsServerNegativePort(t *testing.T) {
	oldPort := MetricsPort
	t.Cleanup(func() {
		MetricsPort = oldPort
	})

	MetricsPort = -1

	done := make(chan struct{}, 1)
	go func() {
		StartMetricsServer()
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StartMetricsServer should return immediately when MetricsPort < 0")
	}
}

func TestBuildMetricsServerTimeouts(t *testing.T) {
	srv := buildMetricsServer(":9090")

	if srv.Addr != ":9090" {
		t.Fatalf("addr = %q, want %q", srv.Addr, ":9090")
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want %s", srv.ReadHeaderTimeout, 5*time.Second)
	}
	if srv.ReadTimeout != 10*time.Second {
		t.Fatalf("ReadTimeout = %s, want %s", srv.ReadTimeout, 10*time.Second)
	}
	if srv.WriteTimeout != 10*time.Second {
		t.Fatalf("WriteTimeout = %s, want %s", srv.WriteTimeout, 10*time.Second)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout = %s, want %s", srv.IdleTimeout, 60*time.Second)
	}
}

func TestRecordSessionSuccess(t *testing.T) {
	totalBefore := testutil.ToFloat64(sessionsTotal)
	failedBefore := testutil.ToFloat64(sessionsFailedTotal)

	recordSession(http.StatusOK)

	if got := testutil.ToFloat64(sessionsTotal) - totalBefore; got != 1 {
		t.Fatalf("sessions total delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(sessionsFailedTotal) - failedBefore; got != 0 {
		t.Fatalf("sessions failed delta = %v, want 0", got)
	}
}

func TestRecordSessionFailure(t *testing.T) {
	totalBefore := testutil.ToFloat64(sessionsTotal)
	failedBefore := testutil.ToFloat64(sessionsFailedTotal)

	recordSession(http.StatusBadGateway)

	if got := testutil.ToFloat64(sessionsTotal) - totalBefore; got != 1 {
		t.Fatalf("sessions total delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(sessionsFailedTotal) - failedBefore; got != 1 {
		t.Fatalf("sessions failed delta = %v, want 1", got)
	}
}

func TestRecordSessionStartObservesLatency(t *testing.T) {
	before := histogramSampleCount(t, sessionStartDuration)

	recordSessionStart(42 * time.Millisecond)

	after := histogramSampleCount(t, sessionStartDuration)
	if got := after - before; got != 1 {
		t.Fatalf("histogram sample delta = %d, want 1", got)
	}
}

func histogramSampleCount(t *testing.T, h interface{ Write(*dto.Metric) error }) uint64 {
	t.Helper()

	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("failed to read histogram metric: %v", err)
	}
	hist := m.GetHistogram()
	if hist == nil {
		t.Fatal("expected histogram metric")
	}
	return hist.GetSampleCount()
}
