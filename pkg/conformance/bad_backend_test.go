package conformance

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// TestMain is where every process badSandbox starts actually gets cleaned
// up: reapGroup only records a pid, so nothing is killed until m.Run() has
// finished and every property has already recorded its result. This also
// sweeps for the one kind of leak reapGroup cannot reach at all, before the
// binary is allowed to exit.
func TestMain(m *testing.M) {
	code := m.Run()
	reapAllTracked()
	sweepDetachedMarkers()
	sweepPlantedArtifacts()
	_ = os.RemoveAll(guestRoot)
	os.Exit(code)
}

// guestScratch is the one guest-only path the suite's probes write into. It
// exists inside any real sandbox and nowhere on a developer's host.
const guestScratch = "/workspace"

// guestRoot is the host directory badSandbox serves guestScratch from, made
// once per run and removed by TestMain.
//
// This makes the control MORE capable of running attacks, not less. Before it,
// every /workspace operation failed with ENOENT on the host, and
// no-traversal-out-of-the-guest "failed" against badBackend only because its
// own positive control fatalled on `ln: /workspace/link: No such file or
// directory` — its three traversal reads and its hostile-filename assertion
// never executed at all, while TestEveryCorePropertyFailsAgainstNoIsolation
// counted the property as negative-control-covered. That is precisely the
// vacuity this suite exists to catch, occurring inside the mechanism built to
// catch it.
//
// Only guestScratch is rerooted, and deliberately so. /etc/shadow, the
// control-plane sockets, /proc, /sys, /dev, /tmp and /dev/shm stay literal
// host paths, because a property that reads a HOST path must still see the
// host — that is the entire content of "this backend isolates nothing". A
// blanket chroot-style reroot of every path would have given badBackend a
// filesystem boundary, which is isolation, and would have turned real
// failures into vacuous passes. Guest scratch is the one prefix with no host
// meaning at all, so serving it from a real directory adds no boundary; it
// only lets the attack land somewhere instead of erroring out before it runs.
var guestRoot = func() string {
	d, err := os.MkdirTemp("", "openblox-conf-badbackend-workspace-*")
	if err != nil {
		panic("conformance: negative control cannot provide " + guestScratch + ": " + err.Error())
	}
	return d
}()

// hostPath maps a guest path onto the host path badSandbox actually uses.
// Everything outside guestScratch is returned unchanged.
func hostPath(p string) string {
	if p == guestScratch {
		return guestRoot
	}
	if rest, ok := strings.CutPrefix(p, guestScratch+"/"); ok {
		return guestRoot + "/" + rest
	}
	return p
}

// rewriteScratch applies hostPath's mapping inside a probe's shell script or
// argv, where guest paths appear as text rather than as an argument to a file
// call. The suite owns every probe string, and guestScratch appears in them
// only as a path, so a plain textual replacement is exact here.
func rewriteScratch(s string) string {
	return strings.ReplaceAll(s, guestScratch, guestRoot)
}

// detachedEscapeMarker is the one marker sweepDetachedMarkers needs to look
// for: propSetsidEscapesTheTimeoutKill's detached "sleep <detachedSleep>". Every
// other process-lifecycle property's marker is already reachable by reapGroup's
// pgid-targeted kill — only setsid moves its child into a new session and
// process group, structurally escaping that. Narrow on purpose: a sweep
// covering the other markers too would be sweeping processes reapGroup
// already handles, for no benefit, at the cost of a wider blast radius on
// whatever else happens to be running on the machine.
var detachedEscapeMarker = detachedSleep

// sweepDetachedMarkers kills any leftover host process that is exactly
// "sleep <detachedSleep>" — argv[0] a "sleep" binary and argv[1] this run's own
// marker, nothing else — by scanning /proc directly. It exists for
// propSetsidEscapesTheTimeoutKill: a setsid-detached process starts its own
// new session and process group, so it is not reachable by reapGroup's
// pgid-targeted kill — the same reason it survives openblox's own timeout
// kill in the real backend. This is a host-hygiene backstop run once after
// the whole suite, not a substitute for that property's own assertions,
// which have already run and recorded their result long before this fires.
//
// The match is on exact argv, not a substring of the raw cmdline: this
// runs against whatever /proc the developer's own machine has, and a
// substring match (the marker anywhere in the line) would also kill an
// unrelated longer sleep, or a script whose path happens to contain the
// digits — unprompted destruction of a process this suite has no business
// touching, on a public repo strangers will run `go test ./...` in without
// having read this file.
func sweepDetachedMarkers() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if len(argv) != 2 || argv[1] != detachedEscapeMarker {
			continue
		}
		prog := argv[0]
		if prog != "sleep" && !strings.HasSuffix(prog, "/sleep") {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// trackedProc is a pid plus the thing that makes it an identity rather than
// a number: the process's start time, field 22 of /proc/<pid>/stat.
//
// A pid alone is not a lifetime-bound handle. Every process here is started
// with Setpgid, so reapAllTracked kills the group with Kill(-pid) — and if the
// process has already exited and the kernel has handed its pid to something
// else, that negated pid names a stranger's process group. On a busy machine
// pid reuse is ordinary, and the blast radius is a SIGKILL to a process group
// this suite has no business touching. Start time is what distinguishes the
// process we launched from whatever now holds its number.
type trackedProc struct {
	pid   int
	start string
}

var (
	trackedMu sync.Mutex
	tracked   []trackedProc
)

// trackForReap records pid so TestMain's reapAllTracked can kill its whole
// process group once the run is over. A process that has already gone by the
// time it is recorded is not tracked at all: there is nothing left to kill,
// and its pid is already eligible for reuse.
func trackForReap(pid int) {
	start, ok := procStart(pid)
	if !ok {
		return
	}
	trackedMu.Lock()
	tracked = append(tracked, trackedProc{pid: pid, start: start})
	trackedMu.Unlock()
}

func reapAllTracked() {
	trackedMu.Lock()
	defer trackedMu.Unlock()
	for _, p := range tracked {
		// Re-read rather than trust the number: if the process is gone, or is
		// now a different process wearing the same pid, this group is not ours
		// to kill.
		if cur, ok := procStart(p.pid); !ok || cur != p.start {
			continue
		}
		_ = syscall.Kill(-p.pid, syscall.SIGKILL)
	}
	tracked = nil
}

// procStart reads a process's start time from /proc/<pid>/stat.
//
// The comm field is parenthesised and may itself contain spaces and
// parentheses, so the fields are counted from the last ')' rather than from
// the start of the line: after it, the first field is state (field 3), which
// puts starttime (field 22) at index 19.
func procStart(pid int) (string, bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", false
	}
	i := strings.LastIndexByte(string(raw), ')')
	if i < 0 {
		return "", false
	}
	f := strings.Fields(string(raw)[i+1:])
	if len(f) < 20 {
		return "", false
	}
	return f[19], true
}

// badBackend is the negative control: it satisfies sandbox.Backend and
// isolates nothing, running every command directly on the host. Core must fail
// against it. It is test-only and must never be exported.
type badBackend struct{}

func newBadBackend() (sandbox.Backend, error) {
	return badBackend{}, nil
}

func (badBackend) Create(_ context.Context, name string, _ ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	return badSandbox{name: name}, nil
}

func (badBackend) Open(_ context.Context, name string) (sandbox.Sandbox, error) {
	return badSandbox{name: name}, nil
}

func (badBackend) List(_ context.Context) ([]sandbox.Info, error) {
	return nil, nil
}

func (badBackend) Destroy(_ context.Context, _ string) error {
	return nil
}

func (badBackend) Close() error {
	return nil
}

// badSandbox runs everything directly on the host process: no isolation
// whatsoever, which is exactly the point of the negative control.
type badSandbox struct {
	name string
}

func (s badSandbox) Info() sandbox.Info {
	return sandbox.Info{Name: s.name, State: sandbox.StateRunning}
}

// reapGroup registers pid's whole process group to be killed once the whole
// test binary is done with it — see TestMain / reapAllTracked. It never
// kills anything itself, and in particular never on a timer: an earlier
// version of this function fired its own kill 5 seconds after Exec or
// StartProcess returned, which held only because every timeout property
// Fatalfs at the ErrTimeout check before it ever reaches countProcs. That
// made the 5-second margin load-bearing but invisible — if badSandbox's
// error handling ever changed to return ErrTimeout, or a slow host pushed a
// property's own countProcs past 5 seconds, the timer could kill the
// process out from under the property and fabricate a green result for the
// wrong reason. Routing all cleanup through TestMain, after every test has
// already run and recorded its result, removes that window entirely: no
// process this backend starts is ever killed while a property could still
// be observing it.
func reapGroup(pid int) {
	trackForReap(pid)
}

// shellQuoteArgv joins argv into a single POSIX shell command line, each
// argument wrapped in single quotes with any embedded single quote escaped
// by closing the quote, emitting an escaped quote, then reopening it.
// Unlike the package's shellQuote (which panics on a single quote or
// newline, because every caller there is a fixed probe constant), this must
// handle arbitrary argv values from any property, so it escapes rather than
// refuses.
func shellQuoteArgv(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

func (badSandbox) Exec(ctx context.Context, cmd sandbox.Command) (sandbox.Result, error) {
	if err := cmd.Validate(); err != nil {
		return sandbox.Result{}, err
	}
	// badBackend enforces no Timeout of its own — honouring the field here,
	// the same way ctx cancellation already works below, keeps a probe that
	// relies on it from hanging the test run forever instead of measuring
	// (correctly) that this backend does not enforce it.
	if cmd.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}

	// Spliced through "sh -c", not exec.Command(cmd.Argv[0], cmd.Argv[1:]...)
	// directly: this is load-bearing, not cosmetic. It models the honest
	// shape of a careless-but-quoting backend — openblox's own docker
	// backend wraps argv in a shell too, to record the process group, and
	// this is that same shape minus the `exec "$0" "$@"` precaution that
	// keeps shell builtins out. Without a shell in the middle, badBackend
	// could never fail propArgvIsNeverAShellBuiltin no matter how little it
	// isolates, which is a defect in the control, not a fact about the
	// property. The quoting shellQuoteArgv does is equally load-bearing in
	// the other direction: a naive strings.Join(argv, " ") was tried and
	// rejected because it breaks other properties into vacuous passes for
	// reasons that have nothing to do with isolation — loopback-is-not-the-
	// hosts and only-a-loopback-interface stop parsing their own probe
	// output correctly, countProcs' `for f in /proc/[0-9]*/cmdline; do ...`
	// pattern degenerates, the output-flood probe keeps 0 bytes, and
	// no-capabilities' grep invocation errors out — each one a new hole a
	// naive join would force into negativeControlExemptions. Correct
	// per-argument quoting avoids all of it: verified empirically, this
	// splice changes nothing about any of the other 20 properties' pass/
	// fail reasons.
	c := exec.Command("sh", "-c", rewriteScratch(shellQuoteArgv(cmd.Argv)))
	c.Env = append(os.Environ(), cmd.Env...)
	c.Dir = cmd.Dir
	c.Stdin = cmd.Stdin
	// Grouped so a background child a probe starts ("cmd &") can be reaped by
	// pgid once the whole test binary is done with it; see reapGroup. Killing
	// the direct process on cancellation still only reaches this one pid, not
	// the group — badBackend leaking a backgrounded child is the correct,
	// honest behaviour of a backend with no isolation, and reapGroup's
	// cleanup, deferred to TestMain, never interferes with a property
	// observing that leak.
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// c.Output()/exec.CommandContext cannot be used here: a probe that
	// backgrounds a child ("cmd &") leaves that child holding its own copy of
	// the stdout/stderr pipes' write end, inherited across the fork. Killing
	// only the direct process (below) never closes that copy, so a read that
	// waits for EOF on the pipe — which is exactly what Output() does —
	// blocks for as long as the leaked child runs, independent of ctx. Piping
	// by hand and bounding the read explicitly is what lets a leaked
	// background child be observable to the property without hanging the
	// test run on it.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return sandbox.Result{}, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return sandbox.Result{}, err
	}
	c.Stdout, c.Stderr = stdoutW, stderrW

	if err := c.Start(); err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
		return sandbox.Result{}, err
	}
	// Our own copies of the write ends must close so EOF can reach the
	// readers once nothing else holds them open; a backgrounded child's own
	// copy, inherited across its fork, is unaffected by this.
	_ = stdoutW.Close()
	_ = stderrW.Close()

	stdoutCh, stderrCh := make(chan []byte, 1), make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(stdoutR); stdoutCh <- b }()
	go func() { b, _ := io.ReadAll(stderrR); stderrCh <- b }()

	waitDone := make(chan error, 1)
	go func() { waitDone <- c.Wait() }()

	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		if c.Process != nil {
			_ = c.Process.Kill()
		}
		waitErr = <-waitDone
	}
	if c.Process != nil {
		reapGroup(c.Process.Pid)
	}

	// The direct process has exited. If a backgrounded child still holds a
	// copy of either write end, unblock the readers after a short grace
	// period rather than waiting on it for as long as that child runs — a
	// leaked child is exactly what the timeout/cancellation properties must
	// be free to observe.
	go func() {
		// A backgrounded child that emits its marker later than this grace
		// period loses it, which can only cost the negative control a
		// failure it should have recorded — never manufacture one. No
		// current probe emits that late; if one ever does, the symptom is a
		// property that stops failing against badBackend, which
		// TestEveryCorePropertyFailsAgainstNoIsolation reports.
		time.Sleep(200 * time.Millisecond)
		_ = stdoutR.Close()
		_ = stderrR.Close()
	}()
	stdout, stderr := <-stdoutCh, <-stderrCh

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return sandbox.Result{}, waitErr
		}
	}
	return sandbox.Result{Stdout: stdout, Stderr: stderr, ExitCode: exitCode}, nil
}

func (badSandbox) WriteFile(_ context.Context, path string, mode fs.FileMode, src io.Reader) error {
	host := hostPath(path)
	// Parent directories are created, but only inside the guest scratch: a
	// real backend materialises the file the caller asked for, so a
	// badSandbox that returned ENOENT for a multi-segment guest path would
	// fatal a property's own positive control and be counted as a negative
	// control failure while having attempted nothing. That is what happened to
	// no-traversal-out-of-the-guest's hostile-filename assertion, whose name
	// deliberately contains "/" characters. Nothing outside guestScratch is
	// created: a write to a host path must still meet the host's own answer.
	if strings.HasPrefix(host, guestRoot+"/") {
		if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(host, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return err
}

func (badSandbox) ReadFile(_ context.Context, path string) (io.ReadCloser, error) {
	return os.Open(hostPath(path))
}

func (badSandbox) StartProcess(_ context.Context, _ string, cmd sandbox.Command) error {
	argv := make([]string, len(cmd.Argv))
	for i, a := range cmd.Argv {
		argv[i] = rewriteScratch(a)
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = append(os.Environ(), cmd.Env...)
	c.Dir = cmd.Dir
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.Start(); err != nil {
		return err
	}
	// badSandbox tracks nothing about a background process once started, the
	// same way it isolates nothing about it while running: nobody else calls
	// Wait, so this reaps it rather than leaving a zombie once TestMain's
	// cleanup kills it.
	go func() { _ = c.Wait() }()
	reapGroup(c.Process.Pid)
	return nil
}

func (badSandbox) Expose(_ context.Context, port int, ttl time.Duration) (sandbox.Preview, error) {
	return sandbox.Preview{
		URL:       "http://127.0.0.1:" + strconv.Itoa(port),
		Token:     "no-isolation",
		Port:      port,
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

func (badSandbox) Revoke(_ context.Context, _ int, _ string) error {
	return nil
}

func (badSandbox) Stop(_ context.Context) error {
	return nil
}
