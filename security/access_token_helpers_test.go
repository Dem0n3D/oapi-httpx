package security

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

func TestValidateUUIDSubject(t *testing.T) {
	t.Parallel()

	if err := ValidateUUIDSubject("not-a-uuid"); err == nil {
		t.Fatal("ValidateUUIDSubject() error = nil, want error")
	}
}

func TestCreateAccessToken(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	tokenString, err := CreateAccessToken(privateKey, "test-key", "4d0bba09-cf39-40d5-9e1f-3f5a4e159b4b", []string{"admin"}, time.Hour)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		PublicKey:       privateKey.Public().(*rsa.PublicKey),
		KeyID:           "test-key",
		ValidateSubject: ValidateUUIDSubject,
	})
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}

	claims, err := verifier.Verify(t.Context(), tokenString)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if claims.Subject != "4d0bba09-cf39-40d5-9e1f-3f5a4e159b4b" {
		t.Fatalf("claims.Subject = %q, want expected uuid", claims.Subject)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "admin" {
		t.Fatalf("claims.Scopes = %#v, want [admin]", claims.Scopes)
	}
}

func TestSignTokenRS256WithoutKeyID(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	claims := NewAccessTokenClaims("4d0bba09-cf39-40d5-9e1f-3f5a4e159b4b", []string{"user"}, time.Now().Add(time.Hour))
	tokenString, err := SignTokenRS256(privateKey, "", claims)
	if err != nil {
		t.Fatalf("SignTokenRS256() error = %v", err)
	}
	if tokenString == "" {
		t.Fatal("SignTokenRS256() returned empty token")
	}

	if err := ValidateUUIDSubject(claims.Subject); err != nil {
		t.Fatalf("ValidateUUIDSubject() error = %v", err)
	}

	if errors.Is(err, ErrEmptyToken) {
		t.Fatal("unexpected error sentinel match")
	}
}
