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
	// Prove the runtime can provide a sandbox before any subtest exists to
	// skip independently. See preflight's doc comment for why this has to
	// happen here, once, rather than inside each property.
	preflight(t, cfg)
	// Visibility of what was measured, on the record rather than inferred
	// from what passed.
	t.Logf("conformance: implementation=%s tier=%s properties=%d image=%s",
		cfg.Name, tier, len(ps), image())
	// Not t.Logf: go test discards a passing non-verbose run's log output, so
	// an overridden run would print "ok" and nothing else — exactly the
	// "presented as a conformant one" case this warning exists to prevent.
	if os.Getenv(imageOverrideEnv) != "" {
		announce("conformance: WARNING %s: image overridden via %s (%s); this run is not a conformant result",
			cfg.Name, imageOverrideEnv, image())
	}
	// A stranger's first failure should not require guessing which claim the
	// property maps to.
	t.Logf("conformance: each property maps to a row in THREAT_MODEL.md; read it there when one fails")

	// Subtests are nested under the tier, so a host-local result can never be
	// read as a Core one in output where the two would otherwise be flat
	// siblings under the caller's own test name.
	t.Run(tier, func(t *testing.T) {
		skipped := 0
		for _, p := range ps {
			t.Run(p.name, func(t *testing.T) {
				defer func() {
					if t.Skipped() {
						skipped++
					}
				}()
				p.fn(t, cfg)
			})
		}
		// Config.New can no longer skip, but a property could still reach a
		// skip by some other route — a helper, a future probe, a t.Skip left
		// behind. A skipped property measured nothing, and a tier that
		// measured nothing must not read as a passing one.
		if skipped > 0 {
			t.Errorf("conformance: %s: tier %s: %d of %d properties skipped; a skipped property is not a passing one",
				cfg.Name, tier, skipped, len(ps))
		}
	})
}

// announce writes a line that must not be lost when a run is reported as
// having passed. t.Logf is not enough on its own: go test discards a passing
// test's log output unless -v is given, so the two things this package most
// needs to say about a green run — "no property was measured" and "the image
// was overridden" — were invisible in exactly the case they matter.
//
// Stderr covers a directly executed test binary, `go test` in local-directory
// mode, any -v run, and any failing run. It does not cover `go test ./...` on
// a package that passes: package-list mode buffers the binary's stdout and
// stderr and prints neither, so nothing written from inside the process
// survives there. /dev/tty is the one channel go test cannot intercept, so
// when stderr has been redirected away from a terminal and a terminal is
// still attached, the line also goes there. In CI, where there is no
// controlling terminal, there is no such channel and the -v output (or the
// skip's own reason) is what remains.
func announce(format string, args ...any) {
	line := fmt.Sprintf(format+"\n", args...)
	fmt.Fprint(os.Stderr, line)
	if isCharDevice(os.Stderr) {
		return
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer func() { _ = tty.Close() }()
	_, _ = tty.WriteString(line)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
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
	_, err := b.Create(t.Context(), preflightSandboxName, sandbox.WithImage(image()))
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
