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

	// ErrTimeout means a command exceeded its deadline. The backend kills the
	// command and its process group, but a process that deliberately detaches
	// (setsid, daemonizing) survives until the sandbox is reaped or destroyed.
	// When the work must stop, Destroy the sandbox. The sandbox itself remains
	// usable.
	ErrTimeout = errors.New("timed out")

	// ErrRuntimeUnavailable means the host cannot provide the required
	// isolation — typically that the gVisor runtime is not installed.
	//
	// Backends must fail with this rather than silently falling back to weaker
	// isolation. A sandbox that is quietly less isolated than requested is worse
	// than no sandbox, because the caller keeps trusting it.
	ErrRuntimeUnavailable = errors.New("required runtime unavailable")

	// ErrStopped means the sandbox exists but is not running, so an operation
	// that needs a live container cannot be served. It is deliberately distinct
	// from ErrNotFound — the sandbox is still there and still inspectable — and
	// from an internal fault, because this is an ordinary, caller-actionable
	// state with a legitimate cause: a sandbox that exhausted its memory cap is
	// killed, which is what the cap is for.
	//
	// A caller that cannot tell this apart from a daemon fault has no way to
	// implement the obvious recovery — notice the sandbox is gone, create a
	// fresh one, tell the user why their state vanished — without re-reading
	// the sandbox after every failure.
	//
	// Note the blast radius: the kill takes the whole sandbox, not the process
	// that overran, so this is a session-ending event rather than a failed
	// command. Anything the sandbox held is gone with it.
	ErrStopped = errors.New("sandbox is stopped")

	// ErrImageUnavailable means the sandbox image could not be obtained: it is
	// absent locally and could not be pulled. Distinct from ErrInvalid because
	// the request was well-formed and retrying may well succeed — a registry
	// being unreachable is a different problem from a misspelled reference.
	ErrImageUnavailable = errors.New("sandbox image unavailable")
)

func newInvalidError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
