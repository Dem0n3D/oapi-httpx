package security

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Dem0n3D/oapi-httpx/requestctx"
	"github.com/golang-jwt/jwt/v5"
)

func TestStrictAuthMiddleware(t *testing.T) {
	t.Parallel()

	type claims struct {
		Scopes []string
	}

	type contextKey string

	const enrichedKey contextKey = "enriched"

	t.Run("passes operation id and enriched context to next handler", func(t *testing.T) {
		t.Parallel()

		middleware := StrictAuthMiddleware(StrictMiddlewareOptions[claims]{
			RequiredScopes: func(context.Context) []string { return []string{"orders:read"} },
			VerifyToken: func(context.Context, string) (*claims, error) {
				return &claims{Scopes: []string{"orders:read"}}, nil
			},
			ClaimsScopes: func(c *claims) []string { return c.Scopes },
			EnrichContext: func(ctx context.Context, token string, _ *claims) context.Context {
				if token != "access-token" {
					t.Fatalf("token = %q, want access-token", token)
				}
				return context.WithValue(ctx, enrichedKey, "ok")
			},
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		nextCalled := false
		handler := middleware(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			nextCalled = true
			if got, _ := ctx.Value(enrichedKey).(string); got != "ok" {
				t.Fatalf("context value = %q, want ok", got)
			}
			w.WriteHeader(http.StatusNoContent)
			return "response", nil
		}, "ListOrders")

		response, err := handler(context.Background(), rec, req, nil)
		if err != nil {
			t.Fatalf("handler error = %v", err)
		}
		if !nextCalled {
			t.Fatal("next handler should be called")
		}
		if response != "response" {
			t.Fatalf("response = %#v, want response", response)
		}
	})

	t.Run("uses operation id in callbacks", func(t *testing.T) {
		t.Parallel()

		var gotOperationID string
		expectedErr := errors.New("bad token")
		middleware := StrictAuthMiddleware(StrictMiddlewareOptions[claims]{
			VerifyToken: func(context.Context, string) (*claims, error) {
				return nil, expectedErr
			},
			OnUnauthorized: func(_ http.ResponseWriter, operationID string, err error) {
				gotOperationID = operationID
				if !errors.Is(err, expectedErr) {
					t.Fatalf("err = %v, want %v", err, expectedErr)
				}
			},
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		handler := middleware(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			t.Fatal("next handler should not be called")
			return nil, nil
		}, "CreateOrder")

		response, err := handler(context.Background(), rec, req, nil)
		if err != nil {
			t.Fatalf("handler error = %v", err)
		}
		if response != nil {
			t.Fatalf("response = %#v, want nil", response)
		}
		if gotOperationID != "CreateOrder" {
			t.Fatalf("operation id = %q, want CreateOrder", gotOperationID)
		}
	})

	t.Run("does not write default response without callbacks", func(t *testing.T) {
		t.Parallel()

		middleware := StrictAuthMiddleware(StrictMiddlewareOptions[claims]{
			RequiredScopes: func(context.Context) []string { return []string{"orders:read"} },
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		handler := middleware(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			t.Fatal("next handler should not be called")
			return nil, nil
		}, "ListOrders")

		if _, err := handler(context.Background(), rec, req, nil); err != nil {
			t.Fatalf("handler error = %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("body = %q, want empty", rec.Body.String())
		}
	})
}

func TestStrictTokenAuthMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("uses token scopes and enriches context", func(t *testing.T) {
		t.Parallel()

		userID := "4d0bba09-cf39-40d5-9e1f-3f5a4e159b4b"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		handler := StrictTokenAuthMiddleware(StrictTokenMiddlewareOptions{
			RequiredScopes: func(context.Context) []string { return []string{"admin"} },
			VerifyToken: func(context.Context, string) (*TokenClaims, error) {
				return &TokenClaims{
					TokenType: TokenTypeAccess,
					Scopes:    []string{"admin"},
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: userID,
					},
				}, nil
			},
		})(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			gotToken, ok := requestctx.AccessTokenFromContext(ctx)
			if !ok || gotToken != "access-token" {
				t.Fatalf("AccessTokenFromContext() = (%q, %v), want (access-token, true)", gotToken, ok)
			}

			gotClaims, ok := requestctx.TokenClaimsFromContext[TokenClaims](ctx)
			if !ok || gotClaims == nil || gotClaims.Subject != userID {
				t.Fatalf("TokenClaimsFromContext() = (%v, %v), want subject %q", gotClaims, ok, userID)
			}

			gotUserID, ok := requestctx.AuthenticatedUserIDFromContext(ctx)
			if !ok || gotUserID.String() != userID {
				t.Fatalf("AuthenticatedUserIDFromContext() = (%v, %v), want %q", gotUserID, ok, userID)
			}

			w.WriteHeader(http.StatusNoContent)
			return nil, nil
		}, "ListOrders")

		if _, err := handler(context.Background(), rec, req, nil); err != nil {
			t.Fatalf("handler error = %v", err)
		}
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})

	t.Run("writes default missing token response", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		handler := StrictTokenAuthMiddleware(StrictTokenMiddlewareOptions{
			RequiredScopes: func(context.Context) []string { return []string{"admin"} },
		})(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			t.Fatal("next handler should not be called")
			return nil, nil
		}, "ListOrders")

		if _, err := handler(context.Background(), rec, req, nil); err != nil {
			t.Fatalf("handler error = %v", err)
		}
		assertErrorResponse(t, rec, http.StatusUnauthorized, "unauthorized", "missing access token")
	})

	t.Run("writes default unauthorized response", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		handler := StrictTokenAuthMiddleware(StrictTokenMiddlewareOptions{
			VerifyToken: func(context.Context, string) (*TokenClaims, error) {
				return nil, ErrTokenRevoked
			},
		})(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			t.Fatal("next handler should not be called")
			return nil, nil
		}, "ListOrders")

		if _, err := handler(context.Background(), rec, req, nil); err != nil {
			t.Fatalf("handler error = %v", err)
		}
		assertErrorResponse(t, rec, http.StatusUnauthorized, "unauthorized", "access token revoked")
	})

	t.Run("writes default forbidden response", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		handler := StrictTokenAuthMiddleware(StrictTokenMiddlewareOptions{
			RequiredScopes: func(context.Context) []string { return []string{"admin"} },
			VerifyToken: func(context.Context, string) (*TokenClaims, error) {
				return &TokenClaims{
					TokenType: TokenTypeAccess,
					Scopes:    []string{"user"},
					RegisteredClaims: jwt.RegisteredClaims{
						Subject: "4d0bba09-cf39-40d5-9e1f-3f5a4e159b4b",
					},
				}, nil
			},
		})(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			t.Fatal("next handler should not be called")
			return nil, nil
		}, "ListOrders")

		if _, err := handler(context.Background(), rec, req, nil); err != nil {
			t.Fatalf("handler error = %v", err)
		}
		assertErrorResponse(t, rec, http.StatusForbidden, "forbidden", "missing required scope")
	})
}

func assertErrorResponse(t *testing.T, rec *httptest.ResponseRecorder, statusCode int, code string, description string) {
	t.Helper()

	if rec.Code != statusCode {
		t.Fatalf("status code = %d, want %d", rec.Code, statusCode)
	}

	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error != code {
		t.Fatalf("error = %q, want %q", body.Error, code)
	}
	if body.ErrorDescription != description {
		t.Fatalf("error description = %q, want %q", body.ErrorDescription, description)
	}
}
