package brokerapi

import (
	"errors"
	"net/http"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Error kinds. The status code alone cannot distinguish every sentinel — two
// map to 503 — so the kind is what the client maps back from.
const (
	KindNotFound           = "not_found"
	KindInvalid            = "invalid"
	KindConflict           = "conflict"
	KindTimeout            = "timeout"
	KindRuntimeUnavailable = "runtime_unavailable"
	KindImageUnavailable   = "image_unavailable"
	KindInternal           = "internal"
)

// ErrProfileConflict means the named sandbox exists under a different profile.
// Returning the live sandbox instead would hand the caller a policy it did not
// ask for, which is exactly the confusion the broker exists to prevent.
var ErrProfileConflict = errors.New("sandbox exists under a different profile")

// ErrInternal is what an unrecognised server-side failure becomes on the
// client. The daemon's own message is logged, not returned: it would describe
// the host's internals to the caller.
var ErrInternal = errors.New("openbloxd: internal error")

// KindOf classifies err for the wire.
func KindOf(err error) (string, int) {
	switch {
	case errors.Is(err, sandbox.ErrNotFound):
		return KindNotFound, http.StatusNotFound
	case errors.Is(err, sandbox.ErrInvalid):
		return KindInvalid, http.StatusBadRequest
	case errors.Is(err, ErrProfileConflict):
		return KindConflict, http.StatusConflict
	case errors.Is(err, sandbox.ErrTimeout):
		return KindTimeout, http.StatusGatewayTimeout
	case errors.Is(err, sandbox.ErrRuntimeUnavailable):
		return KindRuntimeUnavailable, http.StatusServiceUnavailable
	case errors.Is(err, sandbox.ErrImageUnavailable):
		return KindImageUnavailable, http.StatusServiceUnavailable
	default:
		return KindInternal, http.StatusInternalServerError
	}
}

// ErrorFor maps a wire kind back to the sentinel, so a caller's errors.Is
// checks behave the same against the broker as against the library.
func ErrorFor(kind string) error {
	switch kind {
	case KindNotFound:
		return sandbox.ErrNotFound
	case KindInvalid:
		return sandbox.ErrInvalid
	case KindConflict:
		return ErrProfileConflict
	case KindTimeout:
		return sandbox.ErrTimeout
	case KindRuntimeUnavailable:
		return sandbox.ErrRuntimeUnavailable
	case KindImageUnavailable:
		return sandbox.ErrImageUnavailable
	default:
		return ErrInternal
	}
}
