package security

import (
	"crypto/rsa"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func ValidateUUIDSubject(subject string) error {
	_, err := uuid.Parse(strings.TrimSpace(subject))
	return err
}

func NewAccessTokenClaims(subject string, scopes []string, expiresAt time.Time) TokenClaims {
	return TokenClaims{
		TokenType: TokenTypeAccess,
		Scopes:    append([]string(nil), scopes...),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   strings.TrimSpace(subject),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
}

func SignTokenRS256(privateKey *rsa.PrivateKey, keyID string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if strings.TrimSpace(keyID) != "" {
		token.Header["kid"] = strings.TrimSpace(keyID)
	}

	return token.SignedString(privateKey)
}

func CreateAccessToken(privateKey *rsa.PrivateKey, keyID string, subject string, scopes []string, ttl time.Duration) (string, error) {
	claims := NewAccessTokenClaims(subject, scopes, time.Now().Add(ttl))
	return SignTokenRS256(privateKey, keyID, claims)
}
