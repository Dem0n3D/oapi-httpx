package errorsx

import (
	"errors"
	"testing"
)

func TestInternal(t *testing.T) {
	source := errors.New("storage failed")
	err := Internal(source)

	if !IsInternal(err) {
		t.Fatalf("IsInternal() = false, want true")
	}
	if !errors.Is(err, source) {
		t.Fatalf("errors.Is() = false, want true")
	}
}

func TestInternalNil(t *testing.T) {
	if err := Internal(nil); err != nil {
		t.Fatalf("Internal(nil) = %v, want nil", err)
	}
}

func TestInternalf(t *testing.T) {
	err := Internalf("load user: %w", errors.New("not available"))

	if !IsInternal(err) {
		t.Fatalf("IsInternal() = false, want true")
	}
	if got, want := err.Error(), "load user: not available"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
