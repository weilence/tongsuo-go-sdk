package utils

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

type fakeNetError struct {
	err       error
	timeout   bool
	temporary bool
}

func (e fakeNetError) Error() string   { return e.err.Error() }
func (e fakeNetError) Unwrap() error   { return e.err }
func (e fakeNetError) Timeout() bool   { return e.timeout }
func (e fakeNetError) Temporary() bool { return e.temporary }

func TestWrapNetError(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		if err := WrapNetError(nil); err != nil {
			t.Fatalf("WrapNetError(nil) = %v", err)
		}
	})

	t.Run("error without net.Error is unchanged", func(t *testing.T) {
		plain := fmt.Errorf("read: %w", io.ErrUnexpectedEOF)
		if got := WrapNetError(plain); got != plain {
			t.Fatalf("WrapNetError returned %v, want the original error", got)
		}
	})

	t.Run("wrapped timeout keeps net.Error for direct type assertion", func(t *testing.T) {
		// net/http detects aborted background reads by asserting errors
		// directly to net.Error; fmt.Errorf wrapping alone loses that.
		sentinel := errors.New("i/o timeout")
		wrapped := fmt.Errorf("failed to read from connection: %w",
			fakeNetError{err: sentinel, timeout: true, temporary: true})
		if _, ok := wrapped.(net.Error); ok {
			t.Fatal("fmt.Errorf wrapper unexpectedly satisfies net.Error")
		}

		got := WrapNetError(wrapped)
		ne, ok := got.(net.Error)
		if !ok {
			t.Fatalf("wrapped error %v does not satisfy net.Error", got)
		}
		if !ne.Timeout() || !ne.Temporary() {
			t.Fatalf("Timeout()=%v Temporary()=%v, want both true", ne.Timeout(), ne.Temporary())
		}
		if got.Error() != wrapped.Error() {
			t.Fatalf("Error() = %q, want %q", got.Error(), wrapped.Error())
		}
		if !errors.Is(got, sentinel) {
			t.Fatal("errors.Is no longer reaches the wrapped error")
		}
	})

	t.Run("delegates non-timeout verdicts", func(t *testing.T) {
		got := WrapNetError(fmt.Errorf("write: %w", fakeNetError{err: errors.New("broken pipe")}))
		ne, ok := got.(net.Error)
		if !ok {
			t.Fatalf("wrapped error %v does not satisfy net.Error", got)
		}
		if ne.Timeout() || ne.Temporary() {
			t.Fatalf("Timeout()=%v Temporary()=%v, want both false", ne.Timeout(), ne.Temporary())
		}
	})
}
