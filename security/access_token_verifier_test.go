package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAccessTokenVerifierVerify(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	validClaims := TokenClaims{
		TokenType: TokenTypeAccess,
		Scopes:    []string{"admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "token-1",
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	t.Run("verifies valid token", func(t *testing.T) {
		t.Parallel()

		verifier, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
			PublicKey: privateKey.Public().(*rsa.PublicKey),
			KeyID:     "test-key",
			ValidateSubject: func(subject string) error {
				if subject != "user-1" {
					t.Fatalf("subject = %q, want user-1", subject)
				}
				return nil
			},
			IsTokenRevoked: func(context.Context, string) (bool, error) {
				return false, nil
			},
		})
		if err != nil {
			t.Fatalf("NewAccessTokenVerifier() error = %v", err)
		}

		tokenString := signTokenClaims(t, privateKey, "test-key", validClaims)
		claims, err := verifier.Verify(context.Background(), tokenString)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if claims.TokenType != TokenTypeAccess {
			t.Fatalf("claims.TokenType = %q, want %q", claims.TokenType, TokenTypeAccess)
		}
	})

	t.Run("rejects wrong token type", func(t *testing.T) {
		t.Parallel()

		verifier, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
			PublicKey: privateKey.Public().(*rsa.PublicKey),
		})
		if err != nil {
			t.Fatalf("NewAccessTokenVerifier() error = %v", err)
		}

		tokenString := signTokenClaims(t, privateKey, "", TokenClaims{
			TokenType: "refresh",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "user-1",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})

		_, err = verifier.Verify(context.Background(), tokenString)
		if !errors.Is(err, ErrInvalidTokenType) {
			t.Fatalf("Verify() error = %v, want ErrInvalidTokenType", err)
		}
	})

	t.Run("rejects invalid subject", func(t *testing.T) {
		t.Parallel()

		verifier, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
			PublicKey: privateKey.Public().(*rsa.PublicKey),
			ValidateSubject: func(subject string) error {
				if subject == "bad-subject" {
					return errors.New("bad subject")
				}
				return nil
			},
		})
		if err != nil {
			t.Fatalf("NewAccessTokenVerifier() error = %v", err)
		}

		tokenString := signTokenClaims(t, privateKey, "", TokenClaims{
			TokenType: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "bad-subject",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})

		_, err = verifier.Verify(context.Background(), tokenString)
		if !errors.Is(err, ErrInvalidTokenSubject) {
			t.Fatalf("Verify() error = %v, want ErrInvalidTokenSubject", err)
		}
	})

	t.Run("rejects revoked token", func(t *testing.T) {
		t.Parallel()

		verifier, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
			PublicKey: privateKey.Public().(*rsa.PublicKey),
			IsTokenRevoked: func(context.Context, string) (bool, error) {
				return true, nil
			},
		})
		if err != nil {
			t.Fatalf("NewAccessTokenVerifier() error = %v", err)
		}

		tokenString := signTokenClaims(t, privateKey, "", validClaims)
		_, err = verifier.Verify(context.Background(), tokenString)
		if !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("Verify() error = %v, want ErrTokenRevoked", err)
		}
	})
}

func TestNewAccessTokenVerifierFromPEMNormalizesEscapedNewlines(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	verifier, err := NewAccessTokenVerifierFromPEM(strings.ReplaceAll(string(publicKeyPEM), "\n", `\n`), AccessTokenVerifierOptions{
		KeyID:           "test-key",
		ValidateSubject: ValidateUUIDSubject,
	})
	if err != nil {
		t.Fatalf("NewAccessTokenVerifierFromPEM() error = %v", err)
	}

	tokenString := signTokenClaims(t, privateKey, "test-key", TokenClaims{
		TokenType: TokenTypeAccess,
		Scopes:    []string{"admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "4d0bba09-cf39-40d5-9e1f-3f5a4e159b4b",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	if _, err := verifier.Verify(context.Background(), tokenString); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func signTokenClaims(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims TokenClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("token.SignedString() error = %v", err)
	}

	return tokenString
}
