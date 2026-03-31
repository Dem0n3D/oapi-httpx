package render

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]any{
		"ok": true,
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, ok := payload["ok"].(bool); !ok || !got {
		t.Fatalf("payload[ok] = %#v, want true", payload["ok"])
	}
}
