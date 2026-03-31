package security

import (
	"context"
	"net/http"

	"github.com/Dem0n3D/oapi-httpx/requestctx"
	"github.com/google/uuid"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

type StrictMiddlewareOptions[T any] struct {
	RequiredScopes func(context.Context) []string
	VerifyToken    func(context.Context, string) (*T, error)
	ClaimsScopes   func(*T) []string
	EnrichContext  func(context.Context, string, *T) context.Context
	OnMissingToken func(http.ResponseWriter, string, []string)
	OnUnauthorized func(http.ResponseWriter, string, error)
	OnForbidden    func(http.ResponseWriter, string, []string, []string)
}

type StrictTokenMiddlewareOptions struct {
	RequiredScopes func(context.Context) []string
	VerifyToken    func(context.Context, string) (*TokenClaims, error)
	OnMissingToken func(http.ResponseWriter, string, []string)
	OnUnauthorized func(http.ResponseWriter, string, error)
	OnForbidden    func(http.ResponseWriter, string, []string, []string)
}

func StrictAuthMiddleware[T any](opts StrictMiddlewareOptions[T]) strictnethttp.StrictHTTPMiddlewareFunc {
	return func(next strictnethttp.StrictHTTPHandlerFunc, operationID string) strictnethttp.StrictHTTPHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
			nextCtx, authorized := AuthorizeRequest(ctx, w, r, AuthorizeOptions[T]{
				RequiredScopes: opts.RequiredScopes,
				VerifyToken:    opts.VerifyToken,
				ClaimsScopes:   opts.ClaimsScopes,
				EnrichContext:  opts.EnrichContext,
				OnMissingToken: func(w http.ResponseWriter, requiredScopes []string) {
					if opts.OnMissingToken != nil {
						opts.OnMissingToken(w, operationID, requiredScopes)
					}
				},
				OnUnauthorized: func(w http.ResponseWriter, err error) {
					if opts.OnUnauthorized != nil {
						opts.OnUnauthorized(w, operationID, err)
					}
				},
				OnForbidden: func(w http.ResponseWriter, requiredScopes []string, grantedScopes []string) {
					if opts.OnForbidden != nil {
						opts.OnForbidden(w, operationID, requiredScopes, grantedScopes)
					}
				},
			})
			if !authorized {
				return nil, nil
			}

			return next(nextCtx, w, r, request)
		}
	}
}

func StrictTokenAuthMiddleware(opts StrictTokenMiddlewareOptions) strictnethttp.StrictHTTPMiddlewareFunc {
	return StrictAuthMiddleware(StrictMiddlewareOptions[TokenClaims]{
		RequiredScopes: opts.RequiredScopes,
		VerifyToken:    opts.VerifyToken,
		ClaimsScopes: func(claims *TokenClaims) []string {
			if claims == nil {
				return nil
			}
			return claims.Scopes
		},
		EnrichContext: func(ctx context.Context, tokenString string, claims *TokenClaims) context.Context {
			if claims != nil {
				if userID, err := uuid.Parse(claims.Subject); err == nil {
					ctx = requestctx.WithAuthenticatedUserID(ctx, userID)
				}
				ctx = requestctx.WithTokenClaims(ctx, claims)
			}

			return requestctx.WithAccessToken(ctx, tokenString)
		},
		OnMissingToken: func(w http.ResponseWriter, operationID string, requiredScopes []string) {
			if opts.OnMissingToken != nil {
				opts.OnMissingToken(w, operationID, requiredScopes)
				return
			}

			WriteUnauthorized(w, "missing access token")
		},
		OnUnauthorized: func(w http.ResponseWriter, operationID string, err error) {
			if opts.OnUnauthorized != nil {
				opts.OnUnauthorized(w, operationID, err)
				return
			}

			description := DescribeAccessTokenError(err)
			WriteUnauthorized(w, description)
		},
		OnForbidden: func(w http.ResponseWriter, operationID string, requiredScopes []string, grantedScopes []string) {
			if opts.OnForbidden != nil {
				opts.OnForbidden(w, operationID, requiredScopes, grantedScopes)
				return
			}

			WriteForbidden(w, "missing required scope")
		},
	})
}
