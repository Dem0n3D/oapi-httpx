package errorsx

import (
	"errors"
	"fmt"
)

type InternalError struct {
	Err error
}

func (e InternalError) Error() string {
	if e.Err == nil {
		return "internal error"
	}

	return e.Err.Error()
}

func (e InternalError) Unwrap() error {
	return e.Err
}

func Internal(err error) error {
	if err == nil {
		return nil
	}

	return InternalError{Err: err}
}

func Internalf(format string, args ...any) error {
	return Internal(fmt.Errorf(format, args...))
}

func IsInternal(err error) bool {
	var internalErr InternalError
	return errors.As(err, &internalErr)
}
