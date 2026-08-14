package brokerapi

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func TestKindOfRoundTrips(t *testing.T) {
	cases := []struct {
		err    error
		kind   string
		status int
	}{
		{fmt.Errorf("%w: nope", sandbox.ErrNotFound), KindNotFound, http.StatusNotFound},
		{fmt.Errorf("%w: nope", sandbox.ErrInvalid), KindInvalid, http.StatusBadRequest},
		{fmt.Errorf("%w: nope", sandbox.ErrTimeout), KindTimeout, http.StatusGatewayTimeout},
		{fmt.Errorf("%w: nope", sandbox.ErrRuntimeUnavailable), KindRuntimeUnavailable, http.StatusServiceUnavailable},
		{fmt.Errorf("%w: nope", sandbox.ErrImageUnavailable), KindImageUnavailable, http.StatusServiceUnavailable},
		{errors.New("boom"), KindInternal, http.StatusInternalServerError},
	}
	for _, c := range cases {
		kind, status := KindOf(c.err)
		if kind != c.kind || status != c.status {
			t.Errorf("KindOf(%v) = %q/%d, want %q/%d", c.err, kind, status, c.kind, c.status)
		}
		if got := ErrorFor(kind); !errors.Is(got, sentinelFor(t, c.kind)) {
			t.Errorf("ErrorFor(%q) did not map back to the sentinel", kind)
		}
	}
}

func sentinelFor(t *testing.T, kind string) error {
	t.Helper()
	switch kind {
	case KindNotFound:
		return sandbox.ErrNotFound
	case KindInvalid:
		return sandbox.ErrInvalid
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
