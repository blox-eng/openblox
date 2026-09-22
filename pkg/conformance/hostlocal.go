package conformance

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// hostLeakIterations is the number of create/use/destroy cycles
// propHostRetainsNothing measures across. A package constant, not an
// environment variable: a lever that let a caller turn this down from outside
// would be a run that can quietly measure less than it claims, in a tier that
// is already opt-in and so already easier to dodge. See the doc comment on
// imageOverrideEnv for the one deliberate exception this suite makes, and why
// it doesn't apply here — that override announces itself in the run's own
// output; a shorter leak loop would not.
const hostLeakIterations = 15

// propHostRetainsNothing is the host-side half of the old combined leak test.
// "Destroy actually removes the sandbox" is portable and lives in Core as
// propDestroyRemovesTheSandbox; what's left here — goroutine and descriptor
// growth in the test process, and a scan of the host's own /proc for
// processes still serving a destroyed sandbox — can only be measured on the
// machine running the test, so it can never be a Core result.
func propHostRetainsNothing(t *testing.T, cfg Config) {
	b := newBackend(t, cfg)
	ctx := t.Context()
	var ids []string

	// probe is the warm-up cycle's extra duty: prove, while a sandbox is
	// still alive, that scanning /proc for its ID can find it at all. Without
	// that, a backend whose host processes never carry the ID makes the scan
	// below find nothing for a reason that has nothing to do with leaking,
	// and the property passes having measured no process at all.
	cycle := func(i int, probe bool) {
		name := cfg.sbName(fmt.Sprintf("openblox-conf-leak-%d", i))
		sb, err := b.Create(ctx, name, sandbox.WithImage(image()))
		if err != nil {
			t.Fatalf("%s: Create #%d = %v", cfg.Name, i, err)
		}
		id := sb.Info().ID
		if id == "" {
			t.Fatalf("%s: Info().ID is empty; every scan below would match every process on the host", cfg.Name)
		}
		ids = append(ids, id)
		_, _ = sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "sleep 5 & echo hi"}, Timeout: time.Second})
		// The file path is part of what the descriptor count is meant to
		// cover, so a backend that cannot write or read is not a cycle that
		// measured less — it is a cycle that measured something else.
		if err := sb.WriteFile(ctx, "/workspace/"+plantedFile, 0o644, strings.NewReader("data")); err != nil {
			t.Fatalf("%s: WriteFile #%d = %v; the descriptor count would not cover the file path", cfg.Name, i, err)
		}
		rc, err := sb.ReadFile(ctx, "/workspace/"+plantedFile)
		if err != nil {
			t.Fatalf("%s: ReadFile #%d = %v; the descriptor count would not cover the file path", cfg.Name, i, err)
		}
		_ = rc.Close()
		if probe {
			pid, err := hostProcServing(id)
			if err != nil {
				t.Fatalf("%s: %v", cfg.Name, err)
			}
			if pid == "" {
				t.Fatalf("%s: no host process mentions live sandbox %s, so an absent match after Destroy would prove nothing about process leaks on this backend", cfg.Name, shortID(id))
			}
		}
		if err := b.Destroy(ctx, name); err != nil {
			t.Fatalf("%s: Destroy #%d = %v", cfg.Name, i, err)
		}
	}
	// Fails closed: an unreadable /proc/self/fd would otherwise count zero
	// descriptors before and after, and zero growth over zero reads is a pass
	// that measured nothing.
	processLocal := func() (goroutines, fds int) {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatalf("%s: read /proc/self/fd = %v; descriptor growth cannot be measured", cfg.Name, err)
		}
		return runtime.NumGoroutine(), len(entries)
	}

	// One warm-up cycle, so connection pools and lazily started goroutines are
	// part of the baseline rather than counted as growth.
	cycle(-1, true)
	time.Sleep(2 * time.Second)
	g0, f0 := processLocal()

	for i := range hostLeakIterations {
		cycle(i, false)
	}
	time.Sleep(3 * time.Second) // let fire-and-forget bookkeeping execs finish
	g1, f1 := processLocal()
	t.Logf("%s: %d cycles: goroutines %d -> %d, fds %d -> %d", cfg.Name, hostLeakIterations, g0, g1, f0, f1)

	// Small slack: the runtime and the HTTP pool legitimately vary by a few.
	if g1 > g0+5 {
		t.Errorf("%s: goroutines grew %d -> %d", cfg.Name, g0, g1)
	}
	if f1 > f0+5 {
		t.Errorf("%s: file descriptors grew %d -> %d", cfg.Name, f0, f1)
	}

	for _, id := range ids {
		pid, err := hostProcServing(id)
		if err != nil {
			t.Fatalf("%s: %v", cfg.Name, err)
		}
		if pid != "" {
			t.Errorf("%s: host process %s still serves destroyed container %s", cfg.Name, pid, shortID(id))
		}
	}
}

// hostProcServing returns the pid of a host process whose command line
// mentions id, or "" if none does.
//
// It fails closed on an unreadable /proc: being unable to look is not the same
// as having looked and found nothing, and this property reads "found nothing"
// as containment. An individual unreadable cmdline is skipped rather than
// fatal — processes exit while the scan walks them, and treating that as a
// failure would make the property flaky instead of strict.
func hostProcServing(id string) (string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Errorf("read /proc = %w; a host process leak cannot be measured, and an unmeasured scan must not read as containment", err)
	}
	for _, p := range entries {
		cmdline, err := os.ReadFile("/proc/" + p.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if strings.Contains(string(cmdline), id) {
			return p.Name(), nil
		}
	}
	return "", nil
}

// shortID trims a sandbox ID for an error message. Backend IDs have no
// guaranteed length: the suite measures other people's implementations, so a
// fixed id[:12] would panic on a short ID at exactly the moment a leak was
// found — turning the one real finding into a crash.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// propHostFilesAreInvisible is the assertion TestSandboxCannotSeeTheDockerSocketOrHostFiles
// split off: a host temp file, planted by this test process rather than
// baked into the image, must not be visible from inside the guest. It only
// means anything when the backend and the test share a machine, which is why
// it belongs here and not in Core alongside propNoControlPlaneSocket (the
// portable half Task 2 kept: the fixed control-plane socket paths).
func propHostFilesAreInvisible(t *testing.T, cfg Config) {
	marker, err := os.CreateTemp("", "openblox-conf-host-marker-*")
	if err != nil {
		t.Fatalf("%s: CreateTemp = %v", cfg.Name, err)
	}
	_ = marker.Close()
	defer func() { _ = os.Remove(marker.Name()) }()

	b := newBackend(t, cfg)
	sb := create(t, cfg, b, cfg.sbName("openblox-conf-hostfiles"))

	// The marker's path goes through Argv, not a shell string: it is a
	// runtime-generated temp path, not a package constant, so it must never
	// be interpolated into a script the way the fixed control-plane socket
	// paths are.
	res, err := sb.Exec(t.Context(), sandbox.Command{Argv: []string{"test", "-e", marker.Name()}, Timeout: probeTimeout})
	if err == nil && res.ExitCode == 0 {
		t.Errorf("%s: host temp file %s is visible inside the sandbox", cfg.Name, marker.Name())
	}
}
