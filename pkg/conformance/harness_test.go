package conformance

import (
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// unavailableBackend fails every Create with ErrRuntimeUnavailable, as a real
// backend does when the host cannot provide the required runtime. creates
// counts how many times Create was called, so a test can tell a single
// preflight probe apart from one probe per property.
type unavailableBackend struct {
	creates *int
}

func (b unavailableBackend) Create(_ context.Context, _ string, _ ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	*b.creates++
	return nil, sandbox.ErrRuntimeUnavailable
}

func (unavailableBackend) Open(context.Context, string) (sandbox.Sandbox, error) {
	return nil, sandbox.ErrNotFound
}

func (unavailableBackend) List(context.Context) ([]sandbox.Info, error) { return nil, nil }

func (unavailableBackend) Destroy(context.Context, string) error { return nil }

func (unavailableBackend) Close() error { return nil }

var _ sandbox.Backend = unavailableBackend{}

// TestRuntimeUnavailableAbortsRunOnce proves the fix for the fan-out bug: a
// backend that cannot provide the runtime must abort the whole walk exactly
// once, before any property runs, not skip each property independently.
//
// It asserts only observable consequences, not the mechanism used to get
// them:
//   - Backend.Create is called exactly once — the preflight probe — never
//     once per property.
//   - no property function runs.
//   - the parent subtest is the one that stops (via t.Skip's runtime.Goexit,
//     detected by code after the call to Run never executing), not something
//     that lets Run return normally while leaving properties unexercised.
func TestRuntimeUnavailableAbortsRunOnce(t *testing.T) {
	ran := 0
	orig := core
	core = []property{
		{name: "one", fn: func(*testing.T, Config) { ran++ }},
		{name: "two", fn: func(*testing.T, Config) { ran++ }},
		{name: "three", fn: func(*testing.T, Config) { ran++ }},
	}
	t.Cleanup(func() { core = orig })

	creates := 0
	cfg := Config{
		Name: "fake-unavailable",
		New: func() (sandbox.Backend, error) {
			return unavailableBackend{creates: &creates}, nil
		},
	}

	reachedEnd := false
	t.Run("subject", func(t *testing.T) {
		Run(t, cfg)
		// t.Skipf calls runtime.Goexit, which unwinds this goroutine
		// immediately: this line only runs if preflight did NOT skip.
		reachedEnd = true
	})

	if reachedEnd {
		t.Fatal("Run(t, cfg) returned normally after ErrRuntimeUnavailable; want the parent subtest skipped before any property ran")
	}
	if creates != 1 {
		t.Errorf("Backend.Create called %d times, want exactly 1: the preflight is the only place a Core run may probe the runtime", creates)
	}
	if ran != 0 {
		t.Errorf("ran %d properties, want 0: a preflight failure must stop the walk before any property runs, not skip each one independently", ran)
	}
}

// helperCreateFailsHardEnv gates helperCreateFailsHard so it is a no-op
// (Skip) during an ordinary test run, and only does its real work — calling
// create with a backend that returns ErrRuntimeUnavailable — when invoked as
// a subprocess by TestCreateFailsHardOnRuntimeUnavailable below.
const helperCreateFailsHardEnv = "OPENBLOX_CONFORMANCE_TEST_HELPER"

// helperCreateFailsHard is not itself the assertion; it is the subprocess
// TestCreateFailsHardOnRuntimeUnavailable execs to observe create's real
// t.Fatalf, without that failure propagating into this package's own test
// run — a subtest that genuinely fails still fails the enclosing `go test`
// invocation, so proving "this path is a hard failure" has to happen out of
// process.
func helperCreateFailsHard(t *testing.T) {
	if os.Getenv(helperCreateFailsHardEnv) != "1" {
		t.Skip("helper process only; run via TestCreateFailsHardOnRuntimeUnavailable")
	}
	creates := 0
	b := unavailableBackend{creates: &creates}
	create(t, Config{Name: "fake"}, b, "whatever")
}

func TestHelperCreateFailsHard(t *testing.T) { helperCreateFailsHard(t) }

// TestCreateFailsHardOnRuntimeUnavailable proves the other half of the
// ruling: create treats ErrRuntimeUnavailable as a hard failure, never a
// skip. walk's preflight is the only place that error legitimately aborts a
// run; by the time a property calls create, preflight already proved the
// runtime available, so its disappearance now is a real fault, not the
// legitimate abort.
func TestCreateFailsHardOnRuntimeUnavailable(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperCreateFailsHard$", "-test.v")
	cmd.Env = append(os.Environ(), helperCreateFailsHardEnv+"=1")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("subprocess exited 0, want nonzero: create must t.Fatalf on ErrRuntimeUnavailable\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "required runtime unavailable") {
		t.Errorf("subprocess output = %q, want it to name the runtime error", out)
	}
	if strings.Contains(string(out), "SKIP") {
		t.Errorf("subprocess output = %q, want a hard failure, not a skip", out)
	}
}

// trackingBackend is a fake sandbox.Backend that remembers which sandbox
// names are currently live, so a test can assert on what List reports
// instead of on when create/destroy calls happened.
type trackingBackend struct {
	live map[string]bool
}

func newTrackingBackend() *trackingBackend { return &trackingBackend{live: map[string]bool{}} }

func (b *trackingBackend) Create(_ context.Context, name string, _ ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	b.live[name] = true
	return fakeSandbox{}, nil
}

func (b *trackingBackend) Open(_ context.Context, name string) (sandbox.Sandbox, error) {
	if !b.live[name] {
		return nil, sandbox.ErrNotFound
	}
	return fakeSandbox{}, nil
}

func (b *trackingBackend) List(context.Context) ([]sandbox.Info, error) {
	infos := make([]sandbox.Info, 0, len(b.live))
	for name := range b.live {
		infos = append(infos, sandbox.Info{Name: name})
	}
	return infos, nil
}

func (b *trackingBackend) Destroy(_ context.Context, name string) error {
	delete(b.live, name)
	return nil
}

func (b *trackingBackend) Close() error { return nil }

var _ sandbox.Backend = (*trackingBackend)(nil)

// fakeSandbox is the minimal sandbox.Sandbox trackingBackend hands back.
// Nothing in this round exercises it beyond existing.
type fakeSandbox struct{}

func (fakeSandbox) Info() sandbox.Info { return sandbox.Info{} }

func (fakeSandbox) Exec(context.Context, sandbox.Command) (sandbox.Result, error) {
	return sandbox.Result{}, nil
}

func (fakeSandbox) WriteFile(context.Context, string, fs.FileMode, io.Reader) error { return nil }

func (fakeSandbox) ReadFile(context.Context, string) (io.ReadCloser, error) { return nil, nil }

func (fakeSandbox) StartProcess(context.Context, string, sandbox.Command) error { return nil }

func (fakeSandbox) Expose(context.Context, int, time.Duration) (sandbox.Preview, error) {
	return sandbox.Preview{}, nil
}

func (fakeSandbox) Revoke(context.Context, int, string) error { return nil }

func (fakeSandbox) Stop(context.Context) error { return nil }

var _ sandbox.Sandbox = fakeSandbox{}

// TestPreflightDestroysItsSandboxImmediately proves the round-2 fix: the
// preflight sandbox must not outlive preflight itself. Registering its
// destroy only via t.Cleanup on the parent t would leave it live for the
// rest of the tier — every property in core, and under the documented
// Run-then-RunHostLocal usage potentially the next tier too — which is
// exactly the kind of extra state a property reasoning about Backend.List
// should never see.
//
// It asserts the observable consequence, not the call sequence: immediately
// after Run returns (core is empty, so no property's own t.Cleanup has had a
// chance to run either), the preflight sandbox must already be gone from
// List. A t.Cleanup-only implementation would still show it present at this
// point, because t.Cleanup on the parent t fires only after Run's caller's
// test function returns — later than this assertion runs.
func TestPreflightDestroysItsSandboxImmediately(t *testing.T) {
	orig := core
	core = nil
	t.Cleanup(func() { core = orig })

	b := newTrackingBackend()
	cfg := Config{Name: "tracking", New: func() (sandbox.Backend, error) { return b, nil }}

	Run(t, cfg)

	infos, err := b.List(t.Context())
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	for _, info := range infos {
		if info.Name == preflightSandboxName {
			t.Fatalf("List() = %v; preflight sandbox %q is still live immediately after Run returned, want it destroyed before any property could observe it", infos, preflightSandboxName)
		}
	}
}

// TestASkippedPropertyFailsTheTier is the second half of the ruling that
// removed *testing.T from Config.New. The signature change makes the
// measured party unable to skip the suite that measures it — there is no
// *testing.T to call Skip on — but a property could still reach a skip by
// some other route: a helper, a future probe, a t.Skip left behind. A
// skipped property measured nothing, so a tier containing one must not
// report success.
//
// Run out of band via testing.RunTests, for the same reason
// propertyFails does: the failure being asserted is a real failure, and
// observing it in-process would fail this package's own run.
func TestASkippedPropertyFailsTheTier(t *testing.T) {
	orig := core
	core = []property{
		{name: "measures", fn: func(*testing.T, Config) {}},
		{name: "skips", fn: func(t *testing.T, _ Config) { t.Skip("a helper decided this could not run") }},
	}
	t.Cleanup(func() { core = orig })

	b := newTrackingBackend()
	cfg := Config{Name: "skipper", New: func() (sandbox.Backend, error) { return b, nil }}

	passed := testing.RunTests(func(_, _ string) (bool, error) { return true, nil },
		[]testing.InternalTest{{Name: "subject", F: func(t *testing.T) { Run(t, cfg) }}})
	if passed {
		t.Error("a Core run with one skipped property reported success; a skipped property is not a passing one")
	}
}

// TestAnOverriddenImageFailsTheRun holds the claim image.go makes: an
// overridden run cannot be presented as a conformant one. The mechanism is a
// failure rather than a warning, because every announcement channel is
// discardable — go test drops a passing test's log output, and package-list
// mode buffers the binary's stderr too — while a non-zero exit is not.
//
// The override is also checked before preflight, so a host that is both
// overridden and runtime-less still reports the override instead of skipping
// out of walk silently. This test covers that ordering: the backend it uses
// returns ErrRuntimeUnavailable, so a check placed after preflight would let
// the run skip and pass.
func TestAnOverriddenImageFailsTheRun(t *testing.T) {
	orig := core
	core = []property{{name: "measures", fn: func(*testing.T, Config) {}}}
	t.Cleanup(func() { core = orig })
	t.Setenv("OPENBLOX_CONFORMANCE_IMAGE", "example.test/rigged:1")

	creates := 0
	cfg := Config{
		Name: "rigged",
		New:  func() (sandbox.Backend, error) { return unavailableBackend{creates: &creates}, nil },
	}

	passed := testing.RunTests(func(_, _ string) (bool, error) { return true, nil },
		[]testing.InternalTest{{Name: "subject", F: func(t *testing.T) { Run(t, cfg) }}})
	if passed {
		t.Error("a run on an overridden image reported success; the override must fail the run, and must be reported even when the runtime is also unavailable")
	}
}

// helperFilteredTierEnv gates helperFilteredTier the same way
// helperCreateFailsHardEnv gates helperCreateFailsHard: a no-op during an
// ordinary run, real work only as the subprocess below.
const helperFilteredTierEnv = "OPENBLOX_CONFORMANCE_TEST_FILTER_HELPER"

func helperFilteredTier(t *testing.T) {
	if os.Getenv(helperFilteredTierEnv) != "1" {
		t.Skip("helper process only; run via TestAFilteredOutPropertyFailsTheTier")
	}
	orig := core
	core = []property{
		{name: "measures", fn: func(*testing.T, Config) {}},
		{name: "filtered-out", fn: func(*testing.T, Config) {}},
	}
	t.Cleanup(func() { core = orig })

	b := newTrackingBackend()
	Run(t, Config{Name: "filtered", New: func() (sandbox.Backend, error) { return b, nil }})
}

func TestHelperFilteredTier(t *testing.T) { helperFilteredTier(t) }

// TestAFilteredOutPropertyFailsTheTier covers the operator-side half of "no
// Core property is quietly left out": -run or -skip can leave a property out
// entirely, and t.Run's own return value cannot report it, because a filtered
// subtest never runs f and still returns true. A tier that measured fewer
// properties than it claims must not report success.
//
// Out of process, like TestCreateFailsHardOnRuntimeUnavailable, for two
// reasons: the failure being asserted is a real failure, and -test.run is the
// actual mechanism under test — it can only be exercised by a test binary
// invoked with it.
func TestAFilteredOutPropertyFailsTheTier(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperFilteredTier$/^core$/^measures$", "-test.v")
	cmd.Env = append(os.Environ(), helperFilteredTierEnv+"=1")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("subprocess exited 0 with one Core property filtered out by -test.run, want nonzero: a partial run is not a conformant result\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "filtered out by -run/-skip") {
		t.Errorf("subprocess output = %q, want it to name the properties that never ran", out)
	}
}
