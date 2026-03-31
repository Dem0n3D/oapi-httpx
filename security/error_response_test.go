package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteUnauthorized(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteUnauthorized(rec, "missing access token")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error != "unauthorized" {
		t.Fatalf("error = %q, want unauthorized", body.Error)
	}
	if body.ErrorDescription != "missing access token" {
		t.Fatalf("error description = %q, want missing access token", body.ErrorDescription)
	}
}

func TestWriteForbidden(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteForbidden(rec, "missing required scope")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error != "forbidden" {
		t.Fatalf("error = %q, want forbidden", body.Error)
	}
	if body.ErrorDescription != "missing required scope" {
		t.Fatalf("error description = %q, want missing required scope", body.ErrorDescription)
	}
}
