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

	cycle := func(i int) {
		name := fmt.Sprintf("openblox-conf-leak-%d", i)
		sb, err := b.Create(ctx, name, sandbox.WithImage(image()))
		if err != nil {
			t.Fatalf("%s: Create #%d = %v", cfg.Name, i, err)
		}
		ids = append(ids, sb.Info().ID)
		_, _ = sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "sleep 5 & echo hi"}, Timeout: time.Second})
		_ = sb.WriteFile(ctx, "/workspace/"+plantedFile, 0o644, strings.NewReader("data"))
		if rc, err := sb.ReadFile(ctx, "/workspace/"+plantedFile); err == nil {
			_ = rc.Close()
		}
		if err := b.Destroy(ctx, name); err != nil {
			t.Fatalf("%s: Destroy #%d = %v", cfg.Name, i, err)
		}
	}
	processLocal := func() (goroutines, fds int) {
		entries, _ := os.ReadDir("/proc/self/fd")
		return runtime.NumGoroutine(), len(entries)
	}

	// One warm-up cycle, so connection pools and lazily started goroutines are
	// part of the baseline rather than counted as growth.
	cycle(-1)
	time.Sleep(2 * time.Second)
	g0, f0 := processLocal()

	for i := range hostLeakIterations {
		cycle(i)
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

	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		cmdline, err := os.ReadFile("/proc/" + p.Name() + "/cmdline")
		if err != nil {
			continue
		}
		for _, id := range ids {
			if strings.Contains(string(cmdline), id) {
				t.Errorf("%s: host process %s still serves destroyed container %s", cfg.Name, p.Name(), id[:12])
			}
		}
	}
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
	sb := create(t, cfg, b, "openblox-conf-hostfiles")

	// The marker's path goes through Argv, not a shell string: it is a
	// runtime-generated temp path, not a package constant, so it must never
	// be interpolated into a script the way the fixed control-plane socket
	// paths are.
	res, err := sb.Exec(t.Context(), sandbox.Command{Argv: []string{"test", "-e", marker.Name()}})
	if err == nil && res.ExitCode == 0 {
		t.Errorf("%s: host temp file %s is visible inside the sandbox", cfg.Name, marker.Name())
	}
}
