package requestctx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		setup  func(*http.Request)
		wantIP string
	}{
		{
			name: "uses first x forwarded for address",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.10, 198.51.100.20")
				r.RemoteAddr = "127.0.0.1:1234"
			},
			wantIP: "203.0.113.10",
		},
		{
			name: "falls back to x real ip",
			setup: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "203.0.113.20")
				r.RemoteAddr = "127.0.0.1:1234"
			},
			wantIP: "203.0.113.20",
		},
		{
			name: "falls back to remote addr host",
			setup: func(r *http.Request) {
				r.RemoteAddr = "203.0.113.30:4567"
			},
			wantIP: "203.0.113.30",
		},
		{
			name: "uses raw remote addr when split host port fails",
			setup: func(r *http.Request) {
				r.RemoteAddr = "unix-socket"
			},
			wantIP: "unix-socket",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.setup != nil {
				tt.setup(req)
			}

			if got := ExtractClientIP(req); got != tt.wantIP {
				t.Fatalf("ExtractClientIP() = %q, want %q", got, tt.wantIP)
			}
		})
	}
}

func TestMetadataMiddleware(t *testing.T) {
	t.Parallel()

	var gotClientIP string
	var gotUserAgent string

	handler := MetadataMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClientIP = ClientIPFromContext(r.Context())
		gotUserAgent = UserAgentFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("User-Agent", "test-agent")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if gotClientIP != "203.0.113.10" {
		t.Fatalf("ClientIPFromContext() = %q, want 203.0.113.10", gotClientIP)
	}
	if gotUserAgent != "test-agent" {
		t.Fatalf("UserAgentFromContext() = %q, want test-agent", gotUserAgent)
	}
}
