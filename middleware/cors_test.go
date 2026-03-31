package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSOptionsRequest(t *testing.T) {
	t.Parallel()

	called := false
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler should not be called for OPTIONS")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
	}
}

func TestCORSNormalRequest(t *testing.T) {
	t.Parallel()

	called := false
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler should be called for non-OPTIONS request")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusAccepted)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("Access-Control-Allow-Methods header should be set")
	}
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got == "" {
		t.Fatal("Access-Control-Expose-Headers header should be set")
	}
}
