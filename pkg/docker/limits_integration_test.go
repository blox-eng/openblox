//go:build integration

// Adversarial tests for the resource bounds. Every other test here asks whether
// a limit was *set*; these ask whether it *holds* when code inside the sandbox
// actively tries to break it, and whether the host survives the attempt.
//
// The host assertions assume the test process runs on the same machine as the
// Docker daemon, which is how the integration suite is meant to be run. They
// read /proc and statfs directly rather than asking the daemon, because the
// daemon is exactly the component whose containment claim is under test.
package docker

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// lastCounter reads the highest value of a streamed "<prefix><n>" progress line.
// The attacks here kill the shell producing them, so the useful number is the
// last one that made it out rather than anything printed at the end.
func lastCounter(t *testing.T, out, prefix string) int {
	t.Helper()
	last := -1
	for _, line := range strings.Split(out, "\n") {
		_, value, found := strings.Cut(strings.TrimSpace(line), prefix)
		if !found {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		if n > last {
			last = n
		}
	}
	if last < 0 {
		t.Fatalf("no %q progress line in output:\n%s", prefix, out)
	}
	return last
}

// hostProcessCount counts processes on the HOST, not in the sandbox.
func hostProcessCount(t *testing.T) int {
	t.Helper()
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		t.Fatalf("glob /proc = %v", err)
	}
	return len(entries)
}

// hostAvailableBytes reports MemAvailable, which accounts for reclaimable page
// cache and so is the honest measure of "could the host still run something".
func hostAvailableBytes(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Fatalf("read /proc/meminfo = %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			break
		}
		return kb * 1024
	}
	t.Fatal("MemAvailable missing from /proc/meminfo")
	return 0
}

func hostFreeDiskBytes(t *testing.T, path string) int64 {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		t.Fatalf("statfs(%q) = %v", path, err)
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

// assertHostStillUsable proves the host can still do real work. A containment
// claim that leaves the machine wedged has failed even if the sandbox died.
func assertHostStillUsable(t *testing.T, b *Backend, name string) {
	t.Helper()
	start := time.Now()
	sb := create(t, b, name)
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"echo", "alive"},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("host could not run a second sandbox after the attack: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "alive" {
		t.Errorf("second sandbox stdout = %q, want %q", got, "alive")
	}
	// Generous, because this is a liveness check and not a benchmark. It fails
	// only if the host is genuinely struggling.
	if elapsed := time.Since(start); elapsed > 90*time.Second {
		t.Errorf("host took %s to start a trivial sandbox — it is degraded", elapsed)
	}
}

func TestForkBombIsBoundedByTheProcessCap(t *testing.T) {
	b := newTestBackend(t)

	const maxProcs = 64
	sb := create(t, b, "openblox-test-forkbomb", sandbox.WithResources(sandbox.Resources{
		MaxProcesses: maxProcs,
		MemoryBytes:  512 << 20,
		DiskBytes:    64 << 20,
	}))

	hostProcsBefore := hostProcessCount(t)

	// Ask for far more processes than the cap allows, reporting progress as we
	// go. The count has to be streamed rather than printed at the end: when the
	// cap bites, the shell itself dies mid-loop and never reaches a closing
	// statement. `echo` is a builtin, so each line costs no process of its own
	// and the output survives the shell's death.
	const attempts = 400
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c", `
			i=0
			while [ "$i" -lt ` + strconv.Itoa(attempts) + ` ]; do
				sleep 300 &
				i=$((i+1))
				echo "spawned=$i"
			done
		`},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("fork bomb Exec = %v", err)
	}

	got := lastCounter(t, string(res.Stdout), "spawned=")

	// The headline assertion: the sandbox asked for 400 processes and did not
	// get them.
	if got >= attempts {
		t.Errorf("sandbox spawned %d processes with MaxProcesses=%d — the cap is not enforced", got, maxProcs)
	}
	// It must also stop somewhere at or below the cap, not merely somewhere
	// below what it asked for. Note the observed figure sits well under the cap
	// under gVisor: the sentry's own tasks are counted against the same budget,
	// so the guest's usable share is smaller than the number configured. That
	// direction is safe, so the bound is one-sided.
	if got > maxProcs {
		t.Errorf("sandbox spawned %d processes, above its MaxProcesses=%d", got, maxProcs)
	}

	// The host must not have absorbed the overflow. Under gVisor the guest's
	// tasks are not host processes at all, so this should barely move; under a
	// runtime where the cap silently did nothing it would climb by hundreds.
	hostProcsAfter := hostProcessCount(t)
	if delta := hostProcsAfter - hostProcsBefore; delta > 100 {
		t.Errorf("host process count grew by %d (%d -> %d) — the fork bomb reached the host",
			delta, hostProcsBefore, hostProcsAfter)
	}

	assertHostStillUsable(t, b, "openblox-test-forkbomb-witness")
}

func TestMemoryHogIsKilledAndTheHostSurvives(t *testing.T) {
	b := newTestBackend(t)

	const memCap = 128 << 20 // 128 MiB
	sb := create(t, b, "openblox-test-oom", sandbox.WithResources(sandbox.Resources{
		MemoryBytes:  memCap,
		DiskBytes:    32 << 20,
		MaxProcesses: 64,
	}))

	hostAvailBefore := hostAvailableBytes(t)

	// Repeated doubling of a shell string: anonymous memory, no files, so this
	// tests the memory cap rather than the tmpfs budget. Doubling (rather than
	// appending a fixed block) matters — linear growth by string concatenation
	// is quadratic work and spends the whole timeout without ever reaching the
	// cap, which looks like a passing test for the wrong reason.
	//
	// 40 doublings from 16 bytes is ~17 TiB, so completing the loop is only
	// possible if nothing bounded it at all.
	const doublings = 40
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c", `
			s=xxxxxxxxxxxxxxxx
			n=0
			while [ "$n" -lt ` + strconv.Itoa(doublings) + ` ]; do
				s=$s$s
				n=$((n+1))
				echo "doubled=$n"
			done
		`},
		Timeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("memory hog Exec = %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("memory hog exited 0 — it allocated without bound inside a %d-byte cap", memCap)
	}

	// Where it died is the substantive check: the last successful doubling puts
	// an upper bound on how much it ever held. Allow an order of magnitude over
	// the cap to absorb allocator slack, and still catch a cap that did nothing.
	reached := lastCounter(t, string(res.Stdout), "doubled=")
	if held := int64(16) << uint(reached); held > 8*int64(memCap) {
		t.Errorf("sandbox grew to ~%d bytes against a %d-byte cap (%d doublings)", held, memCap, reached)
	}

	// The host is the real subject here: a sandbox that cannot be capped takes
	// the machine with it. Allow a wide margin for unrelated activity, but not
	// enough to hide the sandbox having eaten far past its cap.
	hostAvailAfter := hostAvailableBytes(t)
	if drop := hostAvailBefore - hostAvailAfter; drop > 4*int64(memCap) {
		t.Errorf("host MemAvailable fell by %d bytes against a %d-byte sandbox cap — the cap did not contain it",
			drop, memCap)
	}

	assertHostStillUsable(t, b, "openblox-test-oom-witness")
}

func TestFillingScratchHitsTheDiskCapNotTheHost(t *testing.T) {
	b := newTestBackend(t)

	const diskCap = 32 << 20 // 32 MiB
	sb := create(t, b, "openblox-test-diskfill", sandbox.WithResources(sandbox.Resources{
		MemoryBytes:  256 << 20,
		DiskBytes:    diskCap,
		MaxProcesses: 64,
	}))

	// /var/lib/docker is where an escape would land, so that is the filesystem
	// worth watching rather than the root of wherever the test happens to run.
	const watch = "/var/lib/docker"
	hostFreeBefore := hostFreeDiskBytes(t, watch)

	// Write an order of magnitude past the scratch budget. Because scratch is
	// tmpfs, hitting the cap is also what stops this from becoming a memory
	// exhaustion by another route.
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"sh", "-c", "dd if=/dev/zero of=/tmp/fill bs=1M count=512 2>&1; echo exit=$?"},
		Timeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("disk fill Exec = %v", err)
	}
	if strings.Contains(string(res.Stdout), "exit=0") {
		t.Errorf("wrote 512 MiB into a %d-byte scratch budget without error:\n%s", diskCap, res.Stdout)
	}

	// tmpfs is RAM-backed, so a correctly bounded sandbox cannot have touched
	// the host's disk at all. Only a large regression should trip this.
	hostFreeAfter := hostFreeDiskBytes(t, watch)
	if consumed := hostFreeBefore - hostFreeAfter; consumed > 256<<20 {
		t.Errorf("host free space on %s fell by %d bytes — sandbox writes reached the host disk",
			watch, consumed)
	}

	assertHostStillUsable(t, b, "openblox-test-diskfill-witness")
}
