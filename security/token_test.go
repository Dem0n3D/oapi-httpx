package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractAccessToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		setup  func(*http.Request)
		token  string
		ok     bool
	}{
		{
			name: "authorization header takes precedence",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer access-token")
				r.Header.Set("X-Authorization", "Bearer fallback-token")
				r.Header.Set("X-Access-Token", "plain-token")
			},
			token: "access-token",
			ok:    true,
		},
		{
			name: "x authorization header is used",
			setup: func(r *http.Request) {
				r.Header.Set("X-Authorization", "Bearer access-token")
			},
			token: "access-token",
			ok:    true,
		},
		{
			name: "x access token is trimmed",
			setup: func(r *http.Request) {
				r.Header.Set("X-Access-Token", "  access-token  ")
			},
			token: "access-token",
			ok:    true,
		},
		{
			name: "invalid bearer prefix is ignored",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic access-token")
			},
			ok: false,
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

			token, ok := ExtractAccessToken(req)
			if token != tt.token || ok != tt.ok {
				t.Fatalf("ExtractAccessToken() = (%q, %v), want (%q, %v)", token, ok, tt.token, tt.ok)
			}
		})
	}
}
