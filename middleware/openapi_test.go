package middleware

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestOpenAPIValidation(t *testing.T) {
	t.Parallel()

	spec := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "test",
			Version: "1.0.0",
		},
		Paths: openapi3.NewPaths(
			openapi3.WithPath("/orders", &openapi3.PathItem{
				Get: &openapi3.Operation{
					Parameters: openapi3.Parameters{
						&openapi3.ParameterRef{
							Value: &openapi3.Parameter{
								In:       "query",
								Name:     "limit",
								Required: true,
								Schema: &openapi3.SchemaRef{
									Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}},
								},
							},
						},
					},
					Responses: openapi3.NewResponses(
						openapi3.WithStatus(http.StatusOK, &openapi3.ResponseRef{
							Value: &openapi3.Response{Description: stringPtr("ok")},
						}),
					),
				},
			}),
		),
	}

	mw, err := OpenAPIValidation(func() (*openapi3.T, error) {
		return spec, nil
	})
	if err != nil {
		t.Fatalf("OpenAPIValidation() error = %v", err)
	}

	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("passes valid request", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/orders?limit=10", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNoContent)
		}
		if !nextCalled {
			t.Fatal("next handler should be called")
		}
	})

	t.Run("rejects invalid request", func(t *testing.T) {
		t.Parallel()

		nextCalled = false

		req := httptest.NewRequest(http.MethodGet, "/orders?limit=oops", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status code = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if nextCalled {
			t.Fatal("next handler should not be called")
		}

		var body validationErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if body.Error != "invalid_request" {
			t.Fatalf("error code = %q, want invalid_request", body.Error)
		}
		if body.ErrorDescription == "" {
			t.Fatal("error description should be set")
		}
	})

	t.Run("rejects unknown route", func(t *testing.T) {
		t.Parallel()

		nextCalled = false

		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNotFound)
		}
		if nextCalled {
			t.Fatal("next handler should not be called")
		}
	})
}

func TestOpenAPIValidationWithBasePath(t *testing.T) {
	t.Parallel()

	spec := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "test",
			Version: "1.0.0",
		},
		Paths: openapi3.NewPaths(
			openapi3.WithPath("/orders", &openapi3.PathItem{
				Get: &openapi3.Operation{
					Responses: openapi3.NewResponses(
						openapi3.WithStatus(http.StatusOK, &openapi3.ResponseRef{
							Value: &openapi3.Response{Description: stringPtr("ok")},
						}),
					),
				},
			}),
		),
	}

	mw, err := OpenAPIValidationWithOptions(func() (*openapi3.T, error) {
		return spec, nil
	}, OpenAPIValidationOptions{BasePath: "/auth"})
	if err != nil {
		t.Fatalf("OpenAPIValidationWithOptions() error = %v", err)
	}

	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/auth/orders", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if !nextCalled {
		t.Fatal("next handler should be called")
	}
}

func TestOpenAPIValidationWithBasePathPreservesJSONBodyForNextHandler(t *testing.T) {
	t.Parallel()

	spec := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "test",
			Version: "1.0.0",
		},
		Paths: openapi3.NewPaths(
			openapi3.WithPath("/phone/start", &openapi3.PathItem{
				Post: &openapi3.Operation{
					RequestBody: &openapi3.RequestBodyRef{
						Value: &openapi3.RequestBody{
							Required: true,
							Content: openapi3.NewContentWithJSONSchema(
								&openapi3.Schema{
									Type: &openapi3.Types{"object"},
									Properties: openapi3.Schemas{
										"phone": &openapi3.SchemaRef{
											Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
										},
									},
									Required: []string{"phone"},
								},
							),
						},
					},
					Responses: openapi3.NewResponses(
						openapi3.WithStatus(http.StatusOK, &openapi3.ResponseRef{
							Value: &openapi3.Response{Description: stringPtr("ok")},
						}),
					),
				},
			}),
		),
	}

	mw, err := OpenAPIValidationWithOptions(func() (*openapi3.T, error) {
		return spec, nil
	}, OpenAPIValidationOptions{BasePath: "/auth"})
	if err != nil {
		t.Fatalf("OpenAPIValidationWithOptions() error = %v", err)
	}

	var nextBody string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("io.ReadAll() error = %v", err)
		}
		nextBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/phone/start", strings.NewReader(`{"phone":"+79991234567"}`))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if nextBody != `{"phone":"+79991234567"}` {
		t.Fatalf("next handler body = %q, want %q", nextBody, `{"phone":"+79991234567"}`)
	}
}

func TestOpenAPIValidationReturnsLoadError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("boom")
	_, err := OpenAPIValidation(func() (*openapi3.T, error) {
		return nil, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("OpenAPIValidation() error = %v, want %v", err, expectedErr)
	}
}

func TestWriteValidationError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeValidationError(rec, http.StatusUnauthorized, errors.New("token is invalid"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var body validationErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error != "unauthorized" {
		t.Fatalf("error code = %q, want unauthorized", body.Error)
	}
	if body.ErrorDescription != "token is invalid" {
		t.Fatalf("error description = %q, want token is invalid", body.ErrorDescription)
	}
}

func TestNormalizeBasePath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "root", input: "/", want: ""},
		{name: "plain", input: "auth", want: "/auth"},
		{name: "normalized", input: "/auth/", want: "/auth"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := NormalizeBasePath(tc.input); got != tc.want {
				t.Fatalf("NormalizeBasePath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func stringPtr(value string) *string {
	return &value
}
