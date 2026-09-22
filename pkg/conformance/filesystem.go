package conformance

import (
	"strings"
	"testing"
)

// controlPlaneSockets are the sockets that own the machine. Reaching any of
// them from inside a sandbox is a host takeover, not a containment weakness.
//
// Suite-owned and not configurable: a Config field for probe targets would let
// an implementation narrow the list to the ones it happens to pass, and would
// turn a testing library into a request-forgery gadget that runs inside
// somebody else's isolation boundary and reports what it reached.
var controlPlaneSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
	"/run/podman/podman.sock",
	"/run/openbloxd/openbloxd.sock",
}

func propNoControlPlaneSocket(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-sockets")

	for _, p := range controlPlaneSockets {
		// The path is a package constant, so this interpolation cannot carry
		// anything a caller supplied.
		if out := run(t, sb, `[ -e `+shellQuote(p)+` ] && echo PRESENT`); strings.Contains(out, "PRESENT") {
			t.Errorf("%s: %s is visible inside the sandbox", cfg.Name, p)
		}
	}

	// World-readable on the host, root-only in the image: either way the
	// sandbox user must not read it.
	if out := run(t, sb, `cat /etc/shadow >/dev/null 2>&1 && echo READ`); strings.Contains(out, "READ") {
		t.Errorf("%s: sandbox user read /etc/shadow", cfg.Name)
	}
}

// shellQuote single-quotes a package constant for use in a probe. It exists so
// the quoting is visible and reviewable rather than implied by %q, and it
// rejects anything it cannot quote safely rather than emitting it.
func shellQuote(s string) string {
	if strings.ContainsAny(s, "'\n") {
		panic("conformance: probe constant is not safely quotable: " + s)
	}
	return "'" + s + "'"
}
