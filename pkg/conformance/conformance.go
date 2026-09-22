package conformance

import (
	"context"
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
	// Prove the runtime can provide a sandbox before any subtest exists to
	// skip independently. See preflight's doc comment for why this has to
	// happen here, once, rather than inside each property.
	preflight(t, cfg)
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

// preflightSandboxName is the throwaway sandbox preflight creates to prove
// the runtime is available.
const preflightSandboxName = "openblox-conformance-preflight"

// preflight is the single legitimate abort. It runs on the parent t, before
// any property's t.Run exists, and proves the runtime can provide a sandbox
// at all.
//
// This has to happen here rather than inside create: t.Skip only unwinds the
// goroutine of the *testing.T it is called on via runtime.Goexit. Called from
// inside a property's own subtest, that stops the property that hit it and
// nothing else — walk's loop moves on to the next p.name and calls t.Run
// again, so every remaining property independently discovers the same
// unavailable runtime and skips on its own. N properties then produce N
// skips, which reads exactly like N properties that measured containment.
// Calling t.Skipf here, before the loop starts, unwinds walk itself: no
// t.Run for any property ever executes, the reason is logged once, and the
// caller's test function stops.
//
// A runtime that was available for this call and then vanishes mid-walk is a
// different, real failure — not this one. create reports that with
// t.Fatalf, not a skip, because the runtime's disappearance after preflight
// passed is not evidence of anything the suite is trying to measure.
//
// The probe sandbox does not outlive this function: it is destroyed
// immediately, not via t.Cleanup on the parent t, because a t.Cleanup there
// would only fire after every property in the tier (and, under the
// documented Run-then-RunHostLocal usage, potentially the next tier too) has
// finished. Until then, a property that reasons about Backend.List would see
// an entry no property created. A t.Cleanup is still registered, right
// before the immediate destroy, purely as a backstop against that destroy
// itself failing — it must never mask that failure, so an immediate destroy
// error is still reported via t.Fatalf: a backend whose Destroy is
// unreliable here makes every property's own cleanup suspect too.
func preflight(t *testing.T, cfg Config) {
	t.Helper()
	b := cfg.New(t)
	_, err := b.Create(t.Context(), preflightSandboxName, sandbox.WithImage(image()))
	if err != nil {
		if errors.Is(err, sandbox.ErrRuntimeUnavailable) {
			t.Skipf("conformance: %s: the host cannot provide the required runtime (%v); no property can be measured", cfg.Name, err)
		}
		t.Fatalf("conformance: %s: preflight Create(%q) = %v", cfg.Name, preflightSandboxName, err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.WithoutCancel(t.Context()), preflightSandboxName) })
	if err := b.Destroy(t.Context(), preflightSandboxName); err != nil {
		t.Fatalf("conformance: %s: preflight Destroy(%q) = %v; the backend's Destroy is unreliable, so every property's own cleanup is suspect", cfg.Name, preflightSandboxName, err)
	}
}

var core = []property{
	{"no-control-plane-socket", propNoControlPlaneSocket},
	{"no-host-private-or-metadata-addresses", propNoHostOrMetadataAddresses},
	{"loopback-is-not-the-hosts", propLoopbackIsNotTheHosts},
	{"only-a-loopback-interface", propOnlyLoopbackInterface},
	{"cannot-write-kernel-knobs", propCannotWriteKernelKnobs},
	{"no-block-devices", propNoBlockDevices},
	{"no-traversal-out-of-the-guest", propNoTraversalOutOfGuest},
	{"no-capabilities", propNoCapabilities},
	{"writable-mounts-are-noexec-nosuid", propWritableMountsAreNoexecNosuid},
	{"create-refuses-root", propCreateRefusesRoot},
}

var hostLocal []property
