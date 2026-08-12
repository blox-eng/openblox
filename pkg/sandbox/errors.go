package sandbox

import (
	"errors"
	"fmt"
)

// Sentinel errors. Match them with [errors.Is]; backends wrap them with
// context rather than returning them bare.
var (
	// ErrNotFound means no sandbox exists under the requested name.
	ErrNotFound = errors.New("sandbox not found")

	// ErrInvalid means the request was malformed and retrying will not help.
	ErrInvalid = errors.New("invalid request")

	// ErrTimeout means a command exceeded its deadline and was killed. The
	// sandbox itself remains usable.
	ErrTimeout = errors.New("timed out")

	// ErrRuntimeUnavailable means the host cannot provide the required
	// isolation — typically that the gVisor runtime is not installed.
	//
	// Backends must fail with this rather than silently falling back to weaker
	// isolation. A sandbox that is quietly less isolated than requested is worse
	// than no sandbox, because the caller keeps trusting it.
	ErrRuntimeUnavailable = errors.New("required runtime unavailable")

	// ErrImageUnavailable means the sandbox image could not be obtained: it is
	// absent locally and could not be pulled. Distinct from ErrInvalid because
	// the request was well-formed and retrying may well succeed — a registry
	// being unreachable is a different problem from a misspelled reference.
	ErrImageUnavailable = errors.New("sandbox image unavailable")
)

func newInvalidError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
