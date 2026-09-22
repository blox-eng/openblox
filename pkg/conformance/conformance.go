package conformance

import (
	"errors"
	"os"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Config is what an implementation supplies. It is deliberately this small:
// every field a caller could set is a lever for measuring less than claimed.
type Config struct {
	// New returns a fresh Backend. Called once per property, so no property
	// can be affected by state another one left behind.
	New func(t *testing.T) sandbox.Backend

	// Name identifies the implementation in output.
	Name string
}

// property is one named claim about isolation.
type property struct {
	name string
	fn   func(*testing.T, Config)
}

// Run executes the Core tier. Every property runs against every
// implementation: there is no selector, and nothing skips.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	walk(t, cfg, "core", core)
}

// RunHostLocal executes properties whose evidence lives on the machine running
// the test rather than inside the sandbox. Opt-in, and never a Core result.
func RunHostLocal(t *testing.T, cfg Config) {
	t.Helper()
	walk(t, cfg, "host-local", hostLocal)
}

func walk(t *testing.T, cfg Config, tier string, ps []property) {
	t.Helper()
	if cfg.New == nil {
		t.Fatal("conformance: Config.New is required")
	}
	if cfg.Name == "" {
		t.Fatal("conformance: Config.Name is required")
	}
	// Visibility of what was measured, on the record rather than inferred
	// from what passed.
	t.Logf("conformance: implementation=%s tier=%s properties=%d image=%s",
		cfg.Name, tier, len(ps), image())
	if os.Getenv(imageOverrideEnv) != "" {
		t.Logf("conformance: WARNING image overridden via %s; this run is not a conformant result", imageOverrideEnv)
	}
	for _, p := range ps {
		t.Run(p.name, func(t *testing.T) { p.fn(t, cfg) })
	}
}

// abortIfRuntimeUnavailable is the single legitimate abort. The host cannot
// provide the runtime at all, so no property can be measured. It stops the
// whole run rather than letting properties evaporate one at a time, because a
// per-property skip on this error is indistinguishable from containment.
func abortIfRuntimeUnavailable(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, sandbox.ErrRuntimeUnavailable) {
		t.Skipf("conformance: the host cannot provide the required runtime (%v); no property can be measured", err)
	}
}

var core []property

var hostLocal []property
