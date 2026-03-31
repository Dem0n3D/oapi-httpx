package security

import "github.com/golang-jwt/jwt/v5"

const TokenTypeAccess = "access"

type TokenClaims struct {
	TokenType string   `json:"token_type"`
	Scopes    []string `json:"scopes,omitempty"`
	jwt.RegisteredClaims
}

func (c *TokenClaims) GetTokenType() string {
	return c.TokenType
}

func (c *TokenClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
	return &c.RegisteredClaims
}
