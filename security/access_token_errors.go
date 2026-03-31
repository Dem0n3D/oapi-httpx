package security

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func DescribeAccessTokenError(err error) string {
	description := "invalid access token"
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		description = "access token expired"
	case errors.Is(err, ErrInvalidTokenType):
		description = "invalid access token type"
	case errors.Is(err, ErrTokenRevoked):
		description = "access token revoked"
	case errors.Is(err, ErrInvalidTokenSubject):
		description = "invalid access token subject"
	case err != nil && strings.HasPrefix(err.Error(), "failed to validate access token:"):
		description = "failed to validate access token"
	}

	return description
}
