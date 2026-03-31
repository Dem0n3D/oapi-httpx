package security

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrEmptyToken          = errors.New("token is empty")
	ErrInvalidTokenType    = errors.New("invalid access token type")
	ErrTokenRevoked        = errors.New("access token revoked")
	ErrInvalidTokenSubject = errors.New("invalid access token subject")
)

type AccessTokenVerifierOptions struct {
	PublicKey         *rsa.PublicKey
	KeyID             string
	ExpectedTokenType string
	ValidateSubject   func(string) error
	IsTokenRevoked    func(context.Context, string) (bool, error)
}

type AccessTokenVerifier struct {
	publicKey         *rsa.PublicKey
	keyID             string
	expectedTokenType string
	validateSubject   func(string) error
	isTokenRevoked    func(context.Context, string) (bool, error)
}

func NewAccessTokenVerifier(opts AccessTokenVerifierOptions) (*AccessTokenVerifier, error) {
	if opts.PublicKey == nil {
		return nil, errors.New("public key is required")
	}

	expectedTokenType := strings.TrimSpace(opts.ExpectedTokenType)
	if expectedTokenType == "" {
		expectedTokenType = TokenTypeAccess
	}

	return &AccessTokenVerifier{
		publicKey:         opts.PublicKey,
		keyID:             strings.TrimSpace(opts.KeyID),
		expectedTokenType: expectedTokenType,
		validateSubject:   opts.ValidateSubject,
		isTokenRevoked:    opts.IsTokenRevoked,
	}, nil
}

func NewAccessTokenVerifierFromPEM(publicKeyPEM string, opts AccessTokenVerifierOptions) (*AccessTokenVerifier, error) {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(strings.TrimSpace(publicKeyPEM)))
	if err != nil {
		return nil, fmt.Errorf("parse JWT public key: %w", err)
	}

	opts.PublicKey = publicKey
	return NewAccessTokenVerifier(opts)
}

func (v *AccessTokenVerifier) Verify(ctx context.Context, tokenString string) (*TokenClaims, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, ErrEmptyToken
	}

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if v.keyID != "" {
			kid, _ := token.Header["kid"].(string)
			if kid != "" && kid != v.keyID {
				return nil, fmt.Errorf("unexpected key id: %s", kid)
			}
		}

		return v.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid access token claims")
	}
	if claims.TokenType != v.expectedTokenType {
		return nil, fmt.Errorf("%w: %s", ErrInvalidTokenType, claims.TokenType)
	}

	if v.validateSubject != nil {
		if err := v.validateSubject(claims.Subject); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTokenSubject, err)
		}
	}

	if v.isTokenRevoked != nil && strings.TrimSpace(claims.ID) != "" {
		revoked, err := v.isTokenRevoked(ctx, claims.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to validate access token: %w", err)
		}
		if revoked {
			return nil, ErrTokenRevoked
		}
	}

	return claims, nil
}
