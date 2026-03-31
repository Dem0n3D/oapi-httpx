package requestctx

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestContextHelpers(t *testing.T) {
	t.Parallel()

	baseCtx := context.Background()

	ctx := WithClientIP(baseCtx, " 127.0.0.1 ")
	if got := ClientIPFromContext(ctx); got != "127.0.0.1" {
		t.Fatalf("ClientIPFromContext() = %q, want 127.0.0.1", got)
	}

	ctx = WithUserAgent(ctx, " test-agent ")
	if got := UserAgentFromContext(ctx); got != "test-agent" {
		t.Fatalf("UserAgentFromContext() = %q, want test-agent", got)
	}

	userID := uuid.New()
	ctx = WithAuthenticatedUserID(ctx, userID)
	gotUserID, ok := AuthenticatedUserIDFromContext(ctx)
	if !ok || gotUserID != userID {
		t.Fatalf("AuthenticatedUserIDFromContext() = (%v, %v), want (%v, true)", gotUserID, ok, userID)
	}

	ctx = WithAccessToken(ctx, " access-token ")
	gotToken, ok := AccessTokenFromContext(ctx)
	if !ok || gotToken != "access-token" {
		t.Fatalf("AccessTokenFromContext() = (%q, %v), want (access-token, true)", gotToken, ok)
	}
}

func TestAccessTokenFromContextReturnsFalseForEmptyToken(t *testing.T) {
	t.Parallel()

	ctx := WithAccessToken(context.Background(), "   ")
	gotToken, ok := AccessTokenFromContext(ctx)
	if ok || gotToken != "" {
		t.Fatalf("AccessTokenFromContext() = (%q, %v), want (\"\", false)", gotToken, ok)
	}
}

func TestTokenClaimsFromContext(t *testing.T) {
	t.Parallel()

	type claims struct {
		Subject string
	}

	input := &claims{Subject: "user-1"}
	ctx := WithTokenClaims(context.Background(), input)

	got, ok := TokenClaimsFromContext[claims](ctx)
	if !ok || got != input {
		t.Fatalf("TokenClaimsFromContext() = (%v, %v), want (%v, true)", got, ok, input)
	}

	emptyCtx := WithTokenClaims[claims](context.Background(), nil)
	got, ok = TokenClaimsFromContext[claims](emptyCtx)
	if ok || got != nil {
		t.Fatalf("TokenClaimsFromContext(nil) = (%v, %v), want (nil, false)", got, ok)
	}
}
