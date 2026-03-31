package security

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizeRequest(t *testing.T) {
	t.Parallel()

	type claims struct {
		UserID string
		Scopes []string
	}

	type contextKey string

	const enrichedKey contextKey = "enriched"

	t.Run("allows request without token when scopes are not required", func(t *testing.T) {
		t.Parallel()

		verifyCalled := false
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		ctx, ok := AuthorizeRequest(context.Background(), rec, req, AuthorizeOptions[claims]{
			VerifyToken: func(context.Context, string) (*claims, error) {
				verifyCalled = true
				return nil, nil
			},
		})

		if !ok {
			t.Fatal("AuthorizeRequest() should allow request")
		}
		if verifyCalled {
			t.Fatal("VerifyToken() should not be called when token is missing")
		}
		if ctx != req.Context() {
			t.Fatal("AuthorizeRequest() should return the original context")
		}
	})

	t.Run("rejects missing token when scopes are required", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		var missingScopes []string
		_, ok := AuthorizeRequest(context.Background(), rec, req, AuthorizeOptions[claims]{
			RequiredScopes: func(context.Context) []string { return []string{"orders:read"} },
			OnMissingToken: func(_ http.ResponseWriter, scopes []string) {
				missingScopes = scopes
			},
		})

		if ok {
			t.Fatal("AuthorizeRequest() should reject request without token")
		}
		if len(missingScopes) != 1 || missingScopes[0] != "orders:read" {
			t.Fatalf("OnMissingToken() scopes = %v, want [orders:read]", missingScopes)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		expectedErr := errors.New("bad token")
		var gotErr error
		_, ok := AuthorizeRequest(context.Background(), rec, req, AuthorizeOptions[claims]{
			VerifyToken: func(context.Context, string) (*claims, error) {
				return nil, expectedErr
			},
			OnUnauthorized: func(_ http.ResponseWriter, err error) {
				gotErr = err
			},
		})

		if ok {
			t.Fatal("AuthorizeRequest() should reject invalid token")
		}
		if !errors.Is(gotErr, expectedErr) {
			t.Fatalf("OnUnauthorized() error = %v, want %v", gotErr, expectedErr)
		}
	})

	t.Run("rejects token without required scopes", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		var required, granted []string
		_, ok := AuthorizeRequest(context.Background(), rec, req, AuthorizeOptions[claims]{
			RequiredScopes: func(context.Context) []string { return []string{"orders:write"} },
			VerifyToken: func(context.Context, string) (*claims, error) {
				return &claims{Scopes: []string{"orders:read"}}, nil
			},
			ClaimsScopes: func(c *claims) []string {
				return c.Scopes
			},
			OnForbidden: func(_ http.ResponseWriter, reqScopes []string, grantedScopes []string) {
				required = reqScopes
				granted = grantedScopes
			},
		})

		if ok {
			t.Fatal("AuthorizeRequest() should reject insufficient scopes")
		}
		if len(required) != 1 || required[0] != "orders:write" {
			t.Fatalf("OnForbidden() required = %v, want [orders:write]", required)
		}
		if len(granted) != 1 || granted[0] != "orders:read" {
			t.Fatalf("OnForbidden() granted = %v, want [orders:read]", granted)
		}
	})

	t.Run("enriches context on success", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()

		ctx, ok := AuthorizeRequest(context.Background(), rec, req, AuthorizeOptions[claims]{
			RequiredScopes: func(context.Context) []string { return []string{"orders:read"} },
			VerifyToken: func(context.Context, string) (*claims, error) {
				return &claims{UserID: "u1", Scopes: []string{"orders:read"}}, nil
			},
			ClaimsScopes: func(c *claims) []string {
				return c.Scopes
			},
			EnrichContext: func(ctx context.Context, token string, c *claims) context.Context {
				if token != "access-token" {
					t.Fatalf("token = %q, want access-token", token)
				}
				if c.UserID != "u1" {
					t.Fatalf("claims.UserID = %q, want u1", c.UserID)
				}
				return context.WithValue(ctx, enrichedKey, "ok")
			},
		})

		if !ok {
			t.Fatal("AuthorizeRequest() should allow authorized request")
		}
		if got, _ := ctx.Value(enrichedKey).(string); got != "ok" {
			t.Fatalf("enriched context value = %q, want ok", got)
		}
	})
}
