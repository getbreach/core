package turn

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorCodeExtractsFromResponseError(t *testing.T) {
	err := &ResponseError{Operation: "allocate", Code: 486}
	if got := ErrorCode(err); got != 486 {
		t.Fatalf("ErrorCode() = %d, want 486", got)
	}
}

func TestErrorCodeWrapped(t *testing.T) {
	err := fmt.Errorf("open: %w", &ResponseError{Operation: "refresh", Code: 438})
	if got := ErrorCode(err); got != 438 {
		t.Fatalf("ErrorCode() = %d, want 438 (should unwrap)", got)
	}
}

func TestErrorCodeNonResponseError(t *testing.T) {
	if got := ErrorCode(errors.New("timeout")); got != 0 {
		t.Fatalf("ErrorCode() = %d, want 0 for a non-TURN error", got)
	}
	if got := ErrorCode(nil); got != 0 {
		t.Fatalf("ErrorCode(nil) = %d, want 0", got)
	}
}
