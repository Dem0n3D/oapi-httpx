package security

import (
	"context"
	"net/http"
)

type AuthorizeOptions[T any] struct {
	RequiredScopes func(context.Context) []string
	VerifyToken    func(context.Context, string) (*T, error)
	ClaimsScopes   func(*T) []string
	EnrichContext  func(context.Context, string, *T) context.Context
	OnMissingToken func(http.ResponseWriter, []string)
	OnUnauthorized func(http.ResponseWriter, error)
	OnForbidden    func(http.ResponseWriter, []string, []string)
}

func AuthorizeRequest[T any](ctx context.Context, w http.ResponseWriter, r *http.Request, opts AuthorizeOptions[T]) (context.Context, bool) {
	requiredScopes := []string(nil)
	if opts.RequiredScopes != nil {
		requiredScopes = opts.RequiredScopes(ctx)
	}

	tokenString, ok := ExtractAccessToken(r)
	if !ok {
		if len(requiredScopes) > 0 && opts.OnMissingToken != nil {
			opts.OnMissingToken(w, requiredScopes)
			return ctx, false
		}

		return ctx, true
	}

	claims, err := opts.VerifyToken(ctx, tokenString)
	if err != nil {
		if opts.OnUnauthorized != nil {
			opts.OnUnauthorized(w, err)
		}
		return ctx, false
	}

	grantedScopes := []string(nil)
	if opts.ClaimsScopes != nil {
		grantedScopes = opts.ClaimsScopes(claims)
	}

	if len(requiredScopes) > 0 && opts.ClaimsScopes != nil && opts.OnForbidden != nil && !HasRequiredScopes(grantedScopes, requiredScopes) {
		if opts.OnForbidden != nil {
			opts.OnForbidden(w, requiredScopes, grantedScopes)
		}
		return ctx, false
	}

	if opts.EnrichContext != nil {
		ctx = opts.EnrichContext(ctx, tokenString, claims)
	}

	return ctx, true
}
