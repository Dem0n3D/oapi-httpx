package requestctx

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

type contextKey string

const (
	clientIPContextKey            contextKey = "client_ip"
	userAgentContextKey           contextKey = "user_agent"
	authenticatedUserIDContextKey contextKey = "authenticated_user_id"
	accessTokenContextKey         contextKey = "access_token"
	tokenClaimsContextKey         contextKey = "token_claims"
)

func WithClientIP(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, clientIPContextKey, strings.TrimSpace(clientIP))
}

func ClientIPFromContext(ctx context.Context) string {
	value, _ := ctx.Value(clientIPContextKey).(string)
	return strings.TrimSpace(value)
}

func WithUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentContextKey, strings.TrimSpace(userAgent))
}

func UserAgentFromContext(ctx context.Context) string {
	value, _ := ctx.Value(userAgentContextKey).(string)
	return strings.TrimSpace(value)
}

func WithAuthenticatedUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, authenticatedUserIDContextKey, userID)
}

func AuthenticatedUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(authenticatedUserIDContextKey).(uuid.UUID)
	return userID, ok
}

func WithAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, accessTokenContextKey, strings.TrimSpace(token))
}

func AccessTokenFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(accessTokenContextKey).(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}

func WithTokenClaims[T any](ctx context.Context, claims *T) context.Context {
	return context.WithValue(ctx, tokenClaimsContextKey, claims)
}

func TokenClaimsFromContext[T any](ctx context.Context) (*T, bool) {
	value, ok := ctx.Value(tokenClaimsContextKey).(*T)
	return value, ok && value != nil
}
