package conformance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Config is what an implementation supplies. It is deliberately this small:
// every field a caller could set is a lever for measuring less than claimed.
type Config struct {
	// New returns a fresh Backend. Called once per property, so no property
	// can be affected by state another one left behind.
	//
	// It deliberately takes no *testing.T. An earlier signature,
	// func(t *testing.T) sandbox.Backend, handed the measured party the one
	// lever the rest of this package exists to remove: New is called inside
	// every property's subtest, so a New that returned a real backend for
	// preflight and then called t.Skip() skipped all of Core while `go test`
	// printed "ok" and exited 0. Returning an error instead leaves the suite,
	// not the implementation, to decide what a construction failure means —
	// and it means the run fails loudly, because a backend that cannot be
	// constructed has not conformed. The suite closes the Backend itself.
	New func() (sandbox.Backend, error)

	// Name identifies the implementation in output.
	Name string

	// run namespaces every sandbox this run creates. Unexported because it is
	// the suite's bookkeeping, not a knob: walk sets it, and a caller cannot
	// pin two runs to the same value. See sbName.
	run string
}

// sbName qualifies a property's sandbox name with this run's namespace.
//
// The names are otherwise fixed strings, which collide the moment two runs
// share a host: `go test ./...` builds and runs packages in parallel, so two
// consumers of this suite in one module race each other for
// "openblox-conf-net" on the same daemon. The failure is not a clean one —
// each run destroys sandboxes the other is still measuring — so it reads as a
// flaky isolation property rather than as two tests colliding.
func (c Config) sbName(base string) string {
	if c.run == "" {
		return base
	}
	return base + "-" + c.run
}

// newBackend constructs a Backend for one property (or for preflight) and
// registers its Close. A construction error is fatal rather than a skip: see
// Config.New.
func newBackend(t *testing.T, cfg Config) sandbox.Backend {
	t.Helper()
	b, err := cfg.New()
	if err != nil {
		t.Fatalf("conformance: %s: Config.New() = %v; a backend that cannot be constructed has not conformed", cfg.Name, err)
	}
	if b == nil {
		t.Fatalf("conformance: %s: Config.New() returned a nil Backend and no error", cfg.Name)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
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
	// Per walk, not per process: two tiers, or two backends, can legitimately
	// run concurrently in one binary, and they must not share sandbox names
	// either. See Config.sbName.
	cfg.run = newPlantedSuffix()
	// An overridden image fails the run outright, rather than announcing
	// itself and hoping someone reads it.
	//
	// t.Logf was invisible — go test discards a passing test's log output —
	// and writing to stderr does not fix it either: package-list mode buffers
	// the binary's stdout AND stderr and prints neither for a package that
	// passes, which is exactly the case an overridden run would be presented
	// as. Any announcement channel is the wrong instrument here. A failure is
	// not a channel: it is a non-zero exit, visible in every mode, in CI, and
	// to go test -json.
	//
	// It is t.Errorf rather than a registered property on purpose: a property
	// would pollute len(core), the properties=N line below, and the census
	// TestEveryCorePropertyFailsAgainstNoIsolation takes — all load-bearing.
	//
	// And it is before preflight, not after: a host that is both overridden
	// and runtime-less would otherwise t.Skipf out of walk and never report
	// the override at all.
	//
	// The cost lands on the one person who set the variable — suite
	// development — who reads past one deliberate red, and still has
	// `go test -skip`. That is a flag on their own command line, a much weaker
	// threat class than anything the measured party can bake into Config.
	if os.Getenv(imageOverrideEnv) != "" {
		t.Errorf("conformance: %s: image overridden via %s (%s); this run is NOT a conformant result and fails for that reason alone",
			cfg.Name, imageOverrideEnv, image())
	}
	// Prove the runtime can provide a sandbox before any subtest exists to
	// skip independently. See preflight's doc comment for why this has to
	// happen here, once, rather than inside each property.
	preflight(t, cfg)
	// Visibility of what was measured, on the record rather than inferred
	// from what passed.
	t.Logf("conformance: implementation=%s tier=%s properties=%d image=%s",
		cfg.Name, tier, len(ps), image())
	// A stranger's first failure should not require guessing which claim the
	// property maps to.
	t.Logf("conformance: each property maps to a row in THREAT_MODEL.md; read it there when one fails")

	// Subtests are nested under the tier, so a host-local result can never be
	// read as a Core one in output where the two would otherwise be flat
	// siblings under the caller's own test name.
	t.Run(tier, func(t *testing.T) {
		skipped, filtered := 0, 0
		for _, p := range ps {
			ran := false
			t.Run(p.name, func(t *testing.T) {
				ran = true
				defer func() {
					if t.Skipped() {
						skipped++
					}
				}()
				p.fn(t, cfg)
			})
			// t.Run's own return value cannot report this: it says whether
			// the subtest failed, and a subtest filtered out by -run or -skip
			// never runs f and still returns true. A flag set inside f is the
			// only thing that distinguishes "ran and passed" from "was never
			// run at all".
			if !ran {
				filtered++
			}
		}
		// Config.New can no longer skip, but a property could still reach a
		// skip by some other route — a helper, a future probe, a t.Skip left
		// behind. A skipped property measured nothing, and a tier that
		// measured nothing must not read as a passing one.
		if skipped > 0 {
			t.Errorf("conformance: %s: tier %s: %d of %d properties skipped; a skipped property is not a passing one",
				cfg.Name, tier, skipped, len(ps))
		}
		// Reported separately because the cause is different: -run or -skip on
		// the operator's own command line, not anything inside the suite. A
		// weaker threat class than a lever in Config, but the tier still must
		// not report success having measured fewer properties than it claims.
		if filtered > 0 {
			t.Errorf("conformance: %s: tier %s: %d of %d properties never ran, filtered out by -run/-skip; a partial run is not a conformant result",
				cfg.Name, tier, filtered, len(ps))
		}
	})
}

// announce writes a line to stderr for the one thing this package has to say
// about a run that legitimately measured nothing: the preflight skip.
//
// It supplements the skip, it does not carry it. The machine-readable channel
// is the skip itself — a first-class test2json event, so `go test -json`,
// gotestsum and CI reporters see Action:"skip" with the reason even on an
// otherwise-green package-list run. This line is for the human reading a
// terminal, where stderr covers a directly executed binary, local-directory
// mode, any -v run and any failing run.
//
// The one thing it is deliberately NOT used for any more is the image
// override. Package-list mode buffers a passing package's stdout and stderr
// and prints neither, so no announcement survives the case that matters; an
// override is a failure instead. See walk. Writing to /dev/tty was tried and
// removed: it covers only a human at an interactive terminal, misses CI —
// where an unnoticed override does its damage — and is an odd thing for an
// imported library to do to a consumer's terminal.
func announce(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
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
	b := newBackend(t, cfg)
	name := cfg.sbName(preflightSandboxName)
	_, err := b.Create(t.Context(), name, sandbox.WithImage(image()))
	if err != nil {
		if errors.Is(err, sandbox.ErrRuntimeUnavailable) {
			// Announced on stderr as well as through t.Skipf: go test drops a
			// skip's message on a non-verbose run, so a host without the
			// runtime would print "ok", exit 0 and say nothing at all about
			// having measured no property whatsoever.
			announce("conformance: SKIPPED %s: the host cannot provide the required runtime (%v); NO property was measured",
				cfg.Name, err)
			t.Skipf("conformance: %s: the host cannot provide the required runtime (%v); no property can be measured", cfg.Name, err)
		}
		t.Fatalf("conformance: %s: preflight Create(%q) = %v", cfg.Name, name, err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.WithoutCancel(t.Context()), name) })
	if err := b.Destroy(t.Context(), name); err != nil {
		t.Fatalf("conformance: %s: preflight Destroy(%q) = %v; the backend's Destroy is unreliable, so every property's own cleanup is suspect", cfg.Name, name, err)
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
	{"timed-out-command-kills-its-children", propTimedOutCommandKillsChildren},
	{"cancelled-command-is-not-reported-as-timeout", propCancelledCommandIsNotATimeout},
	{"kill-group-waits-for-a-late-group-record", propKillGroupWaitsForLateRecord},
	{"timeout-kill-is-scoped-to-its-own-command", propTimeoutKillIsScopedToItsCommand},
	{"known-escape-setsid-survives-the-timeout-kill", propSetsidEscapesTheTimeoutKill},
	{"output-flood-is-capped-and-the-command-completes", propOutputFloodIsCapped},
	{"sandboxes-share-no-state", propSandboxesShareNoState},
	{"crashed-sandbox-recovers-through-create", propCrashedSandboxRecoversThroughCreate},
	{"stopped-sandbox-is-replaced-by-create", propStoppedSandboxIsReplacedByCreate},
	{"argv-is-never-a-shell-builtin", propArgvIsNeverAShellBuiltin},
	{"destroy-removes-the-sandbox", propDestroyRemovesTheSandbox},
}

var hostLocal = []property{
	{"host-retains-no-process-goroutine-or-descriptor", propHostRetainsNothing},
	{"host-files-are-invisible-to-the-guest", propHostFilesAreInvisible},
}
