package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

func TestRequestLoggerWritesJSON(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer
	handler := chimiddleware.RequestID(RequestLogger(RequestLoggerOptions{Writer: &log})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	})))

	req := httptest.NewRequest(http.MethodPost, "/orders?status=new", nil)
	req.Header.Set(chimiddleware.RequestIDHeader, "req-123")
	req.Header.Set("User-Agent", "test-client")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var entry map[string]any
	if err := json.Unmarshal(log.Bytes(), &entry); err != nil {
		t.Fatalf("log is not valid json: %v\n%s", err, log.String())
	}

	assertStringField(t, entry, "level", "info")
	assertStringField(t, entry, "message", "http request")
	assertStringField(t, entry, "request_id", "req-123")
	assertStringField(t, entry, "method", http.MethodPost)
	assertStringField(t, entry, "path", "/orders")
	assertStringField(t, entry, "query", "status=new")
	assertStringField(t, entry, "user_agent", "test-client")
	assertNumberField(t, entry, "status", http.StatusCreated)
	assertNumberField(t, entry, "bytes_written", 2)

	if _, ok := entry["timestamp"].(string); !ok {
		t.Fatalf("timestamp field = %v, want string", entry["timestamp"])
	}
	if duration, ok := entry["duration_ms"].(float64); !ok || duration < 0 {
		t.Fatalf("duration_ms field = %v, want non-negative number", entry["duration_ms"])
	}
}

func TestRequestLoggerSkipsPath(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer
	handler := RequestLogger(RequestLoggerOptions{
		SkipPaths: []string{"/healthz", "/metrics"},
		Writer:    &log,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if log.Len() != 0 {
		t.Fatalf("log = %q, want empty", log.String())
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestRequestLoggerSkipsBasePath(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer
	handler := RequestLogger(RequestLoggerOptions{
		BasePath:  "/order",
		SkipPaths: []string{"/healthz", "metrics"},
		Writer:    &log,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/order/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if log.Len() != 0 {
		t.Fatalf("log = %q, want empty", log.String())
	}
}

func TestRequestLoggerWritesPanicAsJSON(t *testing.T) {
	var log bytes.Buffer

	handler := RequestLogger(RequestLoggerOptions{Writer: &log})(chimiddleware.Recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})))

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	decoder := json.NewDecoder(&log)
	var panicEntry map[string]any
	if err := decoder.Decode(&panicEntry); err != nil {
		t.Fatalf("panic log is not valid json: %v\n%s", err, log.String())
	}
	assertStringField(t, panicEntry, "level", "error")
	assertStringField(t, panicEntry, "message", "http panic")
	assertStringField(t, panicEntry, "panic", "boom")

	var requestEntry map[string]any
	if err := decoder.Decode(&requestEntry); err != nil {
		t.Fatalf("request log is not valid json: %v\n%s", err, log.String())
	}
	assertStringField(t, requestEntry, "level", "info")
	assertNumberField(t, requestEntry, "status", http.StatusInternalServerError)
}

func TestRequestLoggerWritesPanicAsJSONForSkippedPath(t *testing.T) {
	var log bytes.Buffer

	handler := RequestLogger(RequestLoggerOptions{
		SkipPaths: []string{"/healthz"},
		Writer:    &log,
	})(chimiddleware.Recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	decoder := json.NewDecoder(&log)
	var panicEntry map[string]any
	if err := decoder.Decode(&panicEntry); err != nil {
		t.Fatalf("panic log is not valid json: %v\n%s", err, log.String())
	}
	assertStringField(t, panicEntry, "level", "error")
	assertStringField(t, panicEntry, "message", "http panic")
	assertStringField(t, panicEntry, "panic", "boom")

	var requestEntry map[string]any
	if err := decoder.Decode(&requestEntry); err == nil {
		t.Fatalf("unexpected request log for skipped path: %#v", requestEntry)
	}
}

func assertStringField(t *testing.T, entry map[string]any, field string, want string) {
	t.Helper()

	if got, ok := entry[field].(string); !ok || got != want {
		t.Fatalf("%s field = %v, want %q", field, entry[field], want)
	}
}

func assertNumberField(t *testing.T, entry map[string]any, field string, want float64) {
	t.Helper()

	if got, ok := entry[field].(float64); !ok || got != want {
		t.Fatalf("%s field = %v, want %v", field, entry[field], want)
	}
}
