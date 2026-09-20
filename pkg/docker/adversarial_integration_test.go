//go:build integration

// Adversarial tests: code inside the sandbox actively trying to reach what it
// must not, outlive what it must not, or leak into what comes after it.
//
// Each attack is phrased so that it fails closed. A probe prints a fixed marker
// only when the attack SUCCEEDS, and the assertion is that the marker is absent
// — so a probe that silently fails to run (missing tool, wrong shell) can never
// read as containment. Where that would still be ambiguous, the test first
// proves the probe works against a target it IS allowed to reach.
package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// run executes a shell script in the sandbox and returns its combined output.
func run(t *testing.T, sb sandbox.Sandbox, script string) string {
	t.Helper()
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"sh", "-c", script},
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("Exec(%q) = %v", script, err)
	}
	return string(res.Stdout) + string(res.Stderr)
}

// --- Network ---------------------------------------------------------------

// The egress test in backend_integration_test.go covers one public address.
// These are the targets an attacker actually wants: the host's own services,
// the Docker bridge, cloud metadata, and private ranges — over TCP, HTTPS and
// IPv6.
func TestSandboxCannotReachHostPrivateOrMetadataAddresses(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-net")

	// The probe works: a loopback listener inside the sandbox is reachable.
	if out := run(t, sb, `nc -l -p 18080 >/dev/null 2>&1 & sleep 1; nc -z -w 2 127.0.0.1 18080 && echo LOOPBACK_OK`); !strings.Contains(out, "LOOPBACK_OK") {
		t.Fatalf("probe cannot reach the sandbox's own loopback, so its failures below would prove nothing: %q", out)
	}

	for _, target := range []string{
		"169.254.169.254 80", // cloud metadata
		"172.17.0.1 2375",    // Docker bridge gateway, plaintext API port
		"172.17.0.1 22",      // host via the bridge
		"10.0.0.1 80",
		"192.168.0.1 80",
		"1.1.1.1 443", // HTTPS egress
		"8.8.8.8 53",  // DNS over TCP to a public resolver
	} {
		out := run(t, sb, fmt.Sprintf(`nc -z -w 2 %s && echo REACHED`, target))
		if strings.Contains(out, "REACHED") {
			t.Errorf("sandbox reached %s", target)
		}
	}

	out := run(t, sb, `wget -T 2 -q -O- https://1.1.1.1 >/dev/null 2>&1 && echo REACHED; `+
		`nc -z -w 2 2606:4700:4700::1111 443 && echo REACHED6; `+
		`nslookup -timeout=2 example.com 8.8.8.8 >/dev/null 2>&1 && echo RESOLVED`)
	for _, marker := range []string{"REACHED", "REACHED6", "RESOLVED"} {
		if strings.Contains(out, marker) {
			t.Errorf("egress attempt succeeded: %s in %q", marker, out)
		}
	}
}

// A sandbox's 127.0.0.1 must be its own. If it shared the host's network
// namespace, every service bound to the host's loopback — often unauthenticated
// because "only localhost can reach it" — would be one connect away.
func TestSandboxLoopbackIsNotTheHosts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on host loopback: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-hostlo")

	if out := run(t, sb, fmt.Sprintf(`nc -z -w 2 127.0.0.1 %d && echo REACHED`, port)); strings.Contains(out, "REACHED") {
		t.Errorf("sandbox reached a listener on the HOST's loopback (port %d)", port)
	}
}

func TestSandboxHasOnlyALoopbackInterface(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-ifaces")

	out := run(t, sb, `cat /proc/net/dev`)
	for _, line := range strings.Split(out, "\n") {
		iface, _, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || iface == "lo" {
			continue
		}
		t.Errorf("sandbox has network interface %q; want only lo", iface)
	}
}

// --- Filesystem ------------------------------------------------------------

func TestSandboxCannotSeeTheDockerSocketOrHostFiles(t *testing.T) {
	marker, err := os.CreateTemp("", "openblox-host-marker-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = marker.Close()
	defer os.Remove(marker.Name())

	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-fs")

	for _, p := range []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/run/openbloxd/openbloxd.sock",
		marker.Name(), // a host /tmp file; the sandbox's /tmp is its own tmpfs
	} {
		if out := run(t, sb, fmt.Sprintf(`[ -e %q ] && echo PRESENT`, p)); strings.Contains(out, "PRESENT") {
			t.Errorf("%s is visible inside the sandbox", p)
		}
	}

	// World-readable on the host, root-only in the image: either way the
	// sandbox user must not read it.
	if out := run(t, sb, `cat /etc/shadow >/dev/null 2>&1 && echo READ`); strings.Contains(out, "READ") {
		t.Error("sandbox user read /etc/shadow")
	}
}

// /proc and /sys are gVisor's own synthetic views. A write through either would
// be reconfiguring the kernel the sandbox runs on.
func TestSandboxCannotWriteKernelKnobs(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-procsys")

	out := run(t, sb, `
echo 1 > /proc/sys/vm/drop_caches 2>/dev/null && echo WROTE_PROC_SYS
echo 1 > /proc/sysrq-trigger 2>/dev/null && echo WROTE_SYSRQ
echo x > /sys/kernel/uevent_helper 2>/dev/null && echo WROTE_SYS
cat /proc/kcore >/dev/null 2>&1 && echo READ_KCORE
`)
	for _, marker := range []string{"WROTE_PROC_SYS", "WROTE_SYSRQ", "WROTE_SYS", "READ_KCORE"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: %q", marker, out)
		}
	}
}

func TestSandboxHasNoBlockDevicesAndCannotMakeOne(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-dev")

	out := run(t, sb, `
for d in /dev/* /dev/*/*; do [ -b "$d" ] && echo "BLOCK $d"; done
mknod /tmp/sda b 8 0 2>/dev/null && echo MADE_NODE
mount -t tmpfs none /tmp 2>/dev/null && echo MOUNTED
`)
	for _, marker := range []string{"BLOCK", "MADE_NODE", "MOUNTED"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: %q", marker, out)
		}
	}
}

// File operations run as the sandbox user inside the sandbox, so a symlink or a
// ".." can only resolve within the guest's own filesystem — never the host's,
// and never past what that user may read.
func TestFileOperationsCannotTraverseOutOfTheGuest(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-traverse")
	ctx := context.Background()

	run(t, sb, `ln -s /etc/shadow /workspace/link; ln -s / /workspace/root`)

	for _, p := range []string{"/workspace/link", "/workspace/root/etc/shadow", "/workspace/../etc/shadow"} {
		rc, err := sb.ReadFile(ctx, p)
		if err != nil {
			continue
		}
		body := make([]byte, 64)
		n, _ := rc.Read(body)
		_ = rc.Close()
		if n > 0 {
			t.Errorf("ReadFile(%q) returned %d bytes of a root-only file", p, n)
		}
	}

	// Writing through a symlink into the read-only root must fail, not land.
	err := sb.WriteFile(ctx, "/workspace/root/etc/openblox-planted", 0o644, strings.NewReader("x"))
	if err == nil {
		t.Error("WriteFile through a symlink wrote into the read-only root filesystem")
	}
	// A hostile file name is data, not syntax.
	name := "/workspace/$(touch /tmp/pwned);`touch /tmp/pwned2`\n-rf"
	if err := sb.WriteFile(ctx, name, 0o644, strings.NewReader("x")); err != nil {
		t.Fatalf("WriteFile(hostile name) = %v", err)
	}
	if out := run(t, sb, `[ -e /tmp/pwned ] || [ -e /tmp/pwned2 ] && echo INJECTED`); strings.Contains(out, "INJECTED") {
		t.Error("a file name was executed as shell")
	}
}

// --- Privilege -------------------------------------------------------------

func TestSandboxHoldsNoCapabilities(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-caps")

	out := run(t, sb, `grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status; id -u; id -g`)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 7 {
		t.Fatalf("unexpected probe output: %q", out)
	}
	for _, l := range lines[:5] {
		if _, v, _ := strings.Cut(l, ":"); strings.Trim(strings.TrimSpace(v), "0") != "" {
			t.Errorf("capability set not empty: %q", l)
		}
	}
	if lines[5] == "0" || lines[6] == "0" {
		t.Errorf("running as uid %s gid %s, want non-root", lines[5], lines[6])
	}
}

// Every writable mount is noexec and nosuid, so the guest can neither run a
// binary it wrote nor plant a setuid one.
func TestWritableMountsAreNoexecAndNosuid(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-noexec")

	out := run(t, sb, `
for d in /tmp /workspace /dev/shm; do
  cp /bin/busybox "$d/bb" 2>/dev/null || continue
  chmod 4755 "$d/bb" 2>/dev/null
  "$d/bb" true 2>/dev/null && echo "EXECUTED $d"
done
su -c id root </dev/null 2>/dev/null | grep -q 'uid=0' && echo ESCALATED
`)
	for _, marker := range []string{"EXECUTED", "ESCALATED"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: %q", marker, out)
		}
	}
}

func TestCreateRefusesRoot(t *testing.T) {
	b := newTestBackend(t)
	for _, user := range []string{"0:0", "root", "1000:0"} {
		_, err := b.Create(context.Background(), "openblox-adv-root",
			sandbox.WithImage(testImage), sandbox.WithUser(user))
		if !errors.Is(err, sandbox.ErrInvalid) {
			_ = b.Destroy(context.Background(), "openblox-adv-root")
			t.Errorf("Create(user %q) = %v, want ErrInvalid", user, err)
		}
	}
}

// --- Processes and time ----------------------------------------------------

// countProcs reports how many processes in the sandbox have marker in their
// command line. The pattern brackets the marker's first character so it
// matches the marker but not the probe's own command line, which contains the
// pattern rather than the marker.
func countProcs(t *testing.T, sb sandbox.Sandbox, marker string) int {
	t.Helper()
	//
	// Processes come and go while the loop runs, so a read can fail; stderr is
	// silenced before the input redirection so the shell's own error is too,
	// and only stdout is parsed.
	pattern := "[" + marker[:1] + "]" + marker[1:]
	res, err := sb.Exec(context.Background(), sandbox.Command{Argv: []string{"sh", "-c",
		fmt.Sprintf(`n=0; for f in /proc/[0-9]*/cmdline; do tr '\0' ' ' 2>/dev/null <"$f" | grep -q %q && n=$((n+1)); done; echo $n`, pattern)}})
	if err != nil {
		t.Fatalf("count processes: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if err != nil {
		t.Fatalf("count processes: %q", res.Stdout)
	}
	return n
}

// A timeout that only stops the caller waiting is not a timeout: the command,
// and anything it started, would burn the sandbox's CPU until it was reaped.
func TestTimedOutCommandIsKilledWithItsChildren(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-timeoutkill")

	_, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"sh", "-c", "sleep 3131 & sleep 3132 & while :; do :; done"},
		Timeout: 2 * time.Second,
	})
	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("Exec = %v, want ErrTimeout", err)
	}
	if n := countProcs(t, sb, "sleep 313"); n != 0 {
		t.Errorf("%d child processes outlived the timeout", n)
	}
	if n := countProcs(t, sb, "while :; do :; done"); n != 0 {
		t.Errorf("the timed-out command itself is still running (%d)", n)
	}
	// The sandbox stays usable, as ErrTimeout promises.
	if out := run(t, sb, "echo alive"); !strings.Contains(out, "alive") {
		t.Errorf("sandbox unusable after a timeout: %q", out)
	}
}

// Cancellation — a caller giving up, or a broker client disconnecting — must
// stop the command the same way a timeout does, and must not be reported as one.
func TestCancelledCommandIsKilledAndNotReportedAsTimeout(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-cancel")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(time.Second, cancel)
	_, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sleep", "3133"}})
	if !errors.Is(err, context.Canceled) || errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("Exec = %v, want context.Canceled and not ErrTimeout", err)
	}
	if n := countProcs(t, sb, "sleep 3133"); n != 0 {
		t.Errorf("cancelled command still running (%d)", n)
	}
}

// The kill is scoped to the timed-out command's own process group. A background
// process started earlier — a preview server, say — must survive another
// command timing out.
func TestTimeoutKillIsScopedToItsOwnCommand(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-killscope")
	ctx := context.Background()

	if err := sb.StartProcess(ctx, "server", sandbox.Command{Argv: []string{"sleep", "3135"}}); err != nil {
		t.Fatalf("StartProcess = %v", err)
	}
	_, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "while :; do :; done"}, Timeout: time.Second})
	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("Exec = %v, want ErrTimeout", err)
	}
	if n := countProcs(t, sb, "sleep 3135"); n != 1 {
		t.Errorf("background process count = %d after an unrelated timeout, want 1", n)
	}
}

// A process that leaves the group with setsid survives the kill. That is the
// documented limit, pinned here so the documentation stays true: what bounds
// such a process is the sandbox's CPU and process caps, its lifetime, and
// Destroy.
func TestSetsidEscapesTheTimeoutKill(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-setsid")

	if out := run(t, sb, "command -v setsid || echo MISSING"); strings.Contains(out, "MISSING") {
		t.Skip("image has no setsid")
	}
	_, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"sh", "-c", "setsid sleep 3136 </dev/null >/dev/null 2>&1 & while :; do :; done"},
		Timeout: time.Second,
	})
	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("Exec = %v, want ErrTimeout", err)
	}
	if n := countProcs(t, sb, "sleep 3136"); n != 1 {
		t.Errorf("setsid process count = %d; if the kill now reaches it, update ErrTimeout's documentation", n)
	}
}

func TestOutputFloodIsCappedAndTheCommandCompletes(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-flood")

	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c", `head -c 50000000 /dev/zero; head -c 50000000 /dev/zero >&2; exit 4`},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if !res.Truncated {
		t.Error("Truncated = false after 50 MB on each stream")
	}
	if len(res.Stdout) != sandbox.MaxOutputBytes || len(res.Stderr) != sandbox.MaxOutputBytes {
		t.Errorf("kept %d/%d bytes, want %d on each", len(res.Stdout), len(res.Stderr), sandbox.MaxOutputBytes)
	}
	if res.ExitCode != 4 {
		t.Errorf("exit code = %d, want 4: the stream must be drained so the command finishes", res.ExitCode)
	}
}

// --- Isolation between sandboxes and across a sandbox's life -----------------

func TestSandboxesShareNoStateAndRecreateIsFresh(t *testing.T) {
	t.Setenv("OPENBLOX_HOST_SECRET", "host-secret-value")
	b := newTestBackend(t)
	a := create(t, b, "openblox-adv-iso-a", sandbox.WithEnv("TENANT_TOKEN=a-secret"))
	other := create(t, b, "openblox-adv-iso-b")

	run(t, a, `echo a-data > /workspace/f; echo a-data > /tmp/f; echo a-data > /dev/shm/f 2>/dev/null; true`)

	out := run(t, other, `cat /workspace/f /tmp/f /dev/shm/f 2>/dev/null; env`)
	for _, leaked := range []string{"a-data", "a-secret", "host-secret-value"} {
		if strings.Contains(out, leaked) {
			t.Errorf("sandbox B sees %q", leaked)
		}
	}
	if out := run(t, a, `env`); strings.Contains(out, "host-secret-value") {
		t.Error("the calling process's environment leaked into the sandbox")
	}

	if err := b.Destroy(context.Background(), "openblox-adv-iso-a"); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	again := create(t, b, "openblox-adv-iso-a")
	if out := run(t, again, `cat /workspace/f /tmp/f 2>/dev/null; env`); strings.Contains(out, "a-data") || strings.Contains(out, "a-secret") {
		t.Errorf("a re-created sandbox inherited its predecessor's state: %q", out)
	}
}

// --- Lifecycle -------------------------------------------------------------

// Under gVisor the guest can SIGKILL its own init, which stops the sandbox. That
// harms nothing but the guest itself; what matters is that it surfaces as a
// prompt error rather than a hang, and that Create brings the sandbox back.
func TestCrashedSandboxFailsFastAndRecoversThroughCreate(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	name := "openblox-adv-crash"
	sb := create(t, b, name)

	_, _ = sb.Exec(ctx, sandbox.Command{Argv: []string{"kill", "-9", "1"}, Timeout: 10 * time.Second})

	deadline := time.Now().Add(20 * time.Second)
	for {
		current, err := b.Open(ctx, name)
		if err == nil && current.Info().State == sandbox.StateStopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox still not stopped 20s after its init was killed (err %v)", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	start := time.Now()
	if _, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"true"}}); err == nil {
		t.Error("Exec on a crashed sandbox succeeded")
	}
	if time.Since(start) > 10*time.Second {
		t.Error("Exec on a crashed sandbox hung instead of failing")
	}

	back, err := b.Create(ctx, name, sandbox.WithImage(testImage))
	if err != nil {
		t.Fatalf("Create after crash = %v", err)
	}
	if out := run(t, back, "echo back"); !strings.Contains(out, "back") {
		t.Errorf("sandbox not usable after Create brought it back: %q", out)
	}
}

// A stopped sandbox is replaced, not revived: its writable storage is gone
// anyway, and reviving it would bring back the policy it was created under
// instead of the one asked for now.
func TestStoppedSandboxIsReplacedByCreateUnderTheNewPolicy(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	const name = "openblox-adv-restart"
	sb := create(t, b, name, sandbox.WithLabel("policy", "old"))

	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Stop = %v", err)
	}
	back, err := b.Create(ctx, name, sandbox.WithImage(testImage), sandbox.WithLabel("policy", "new"))
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	if back.Info().State != sandbox.StateRunning {
		t.Errorf("state after Create = %s, want running", back.Info().State)
	}
	if back.Info().ID == sb.Info().ID {
		t.Error("Create restarted the stopped container instead of replacing it")
	}
	if got := back.Info().Labels["policy"]; got != "new" {
		t.Errorf("policy label = %q, want the options passed to this Create", got)
	}
	if out := run(t, back, "echo ok"); !strings.Contains(out, "ok") {
		t.Errorf("Exec after replacement: %q", out)
	}
}

// Argv is executed as a program, never as a shell builtin, even though a shell
// now wraps it to record its process group. "exit 3" as argv names a program
// called exit — which does not exist — not the shell's exit.
func TestArgvIsNeverAShellBuiltin(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-adv-builtin")

	res, err := sb.Exec(context.Background(), sandbox.Command{Argv: []string{"exit", "3"}})
	if err == nil && res.ExitCode == 3 {
		t.Error("argv[0] \"exit\" ran as the shell builtin")
	}
}

// Repeated create/use/destroy must leave nothing behind: no containers, no
// runsc processes serving them, no descriptors or goroutines in the caller.
// Only this test's own containers are tracked, so sandboxes created by other
// packages running in parallel cannot make it flaky. Set
// OPENBLOX_LEAK_ITERATIONS to run longer than the CI default.
func TestRepeatedLifecycleLeaksNothing(t *testing.T) {
	iterations := 15
	if v, err := strconv.Atoi(os.Getenv("OPENBLOX_LEAK_ITERATIONS")); err == nil && v > 0 {
		iterations = v
	}
	b := newTestBackend(t)
	ctx := context.Background()
	var ids []string

	cycle := func(i int) {
		name := fmt.Sprintf("openblox-adv-leak-%d", i)
		sb, err := b.Create(ctx, name, sandbox.WithImage(testImage))
		if err != nil {
			t.Fatalf("Create #%d = %v", i, err)
		}
		ids = append(ids, sb.Info().ID)
		_, _ = sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "sleep 5 & echo hi"}, Timeout: time.Second})
		_ = sb.WriteFile(ctx, "/workspace/f", 0o644, strings.NewReader("data"))
		if rc, err := sb.ReadFile(ctx, "/workspace/f"); err == nil {
			_ = rc.Close()
		}
		if err := b.Destroy(ctx, name); err != nil {
			t.Fatalf("Destroy #%d = %v", i, err)
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

	for i := range iterations {
		cycle(i)
	}
	time.Sleep(3 * time.Second) // let fire-and-forget bookkeeping execs finish
	g1, f1 := processLocal()
	t.Logf("%d cycles: goroutines %d -> %d, fds %d -> %d", iterations, g0, g1, f0, f1)

	// Small slack: the runtime and the HTTP pool legitimately vary by a few.
	if g1 > g0+5 {
		t.Errorf("goroutines grew %d -> %d", g0, g1)
	}
	if f1 > f0+5 {
		t.Errorf("file descriptors grew %d -> %d", f0, f1)
	}

	for _, id := range ids {
		if _, err := b.cli.ContainerInspect(ctx, id); err == nil {
			t.Errorf("container %s survived Destroy", id[:12])
		}
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		cmdline, err := os.ReadFile("/proc/" + p.Name() + "/cmdline")
		if err != nil {
			continue
		}
		for _, id := range ids {
			if strings.Contains(string(cmdline), id) {
				t.Errorf("host process %s still serves destroyed container %s", p.Name(), id[:12])
			}
		}
	}
}
