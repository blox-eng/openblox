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
	"syscall"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// TestMain is where every process badSandbox starts gets cleaned up. Nothing
// is killed while a property could still observe it: the kill happens after
// m.Run() has finished and every property has recorded its result.
//
// The cleanup must also happen when this binary never reaches the end of
// TestMain (a -timeout panic, a SIGKILL, a closed terminal). So a watchdog
// process does the same kill when this one dies, and each run first kills what
// an earlier dead run left. The probes include busy loops, and a leaked one
// holds a full core until someone kills it by hand (#105).
func TestMain(m *testing.M) {
	if owner := os.Getenv(watchdogEnv); owner != "" {
		_, _ = io.Copy(io.Discard, os.Stdin) // returns when the owner dies
		killOwned(owner)
		os.Exit(0)
	}
	killOrphaned()
	startWatchdog()
	code := m.Run()
	killOwned(ownerTag)
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

// ownerEnv marks every process badSandbox starts with the test binary that
// started it. A child inherits its environment, so the mark reaches a
// backgrounded child and a setsid-detached one alike, which a process group
// does not. It also makes the kill exact: this runs on a developer's own
// machine, and a match on argv or on a recycled pid could kill a process this
// suite has no business touching.
const ownerEnv = "OPENBLOX_CONFORMANCE_OWNER"

// watchdogEnv turns this test binary into the watchdog for the named owner.
const watchdogEnv = "OPENBLOX_CONFORMANCE_WATCHDOG"

// ownerTag identifies this test process: its pid and its start time. The pid
// alone is not an identity, because the kernel reuses it.
var ownerTag = func() string {
	start, ok := procStart(os.Getpid())
	if !ok {
		panic("conformance: negative control cannot read its own /proc entry")
	}
	return strconv.Itoa(os.Getpid()) + ":" + start
}()

// procOwners maps every visible process that carries ownerEnv to its owner.
func procOwners() map[int]string {
	owners := map[int]string{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/environ")
		if err != nil {
			continue
		}
		for _, kv := range strings.Split(string(raw), "\x00") {
			if v, ok := strings.CutPrefix(kv, ownerEnv+"="); ok {
				owners[pid] = v
				break
			}
		}
	}
	return owners
}

func ownedProcs(owner string) []int {
	var pids []int
	for pid, o := range procOwners() {
		if o == owner {
			pids = append(pids, pid)
		}
	}
	return pids
}

func killOwned(owner string) {
	for _, pid := range ownedProcs(owner) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// killOrphaned kills what a dead run left behind: every marked process whose
// owner no longer exists. A run that is still alive keeps its processes.
func killOrphaned() {
	for pid, owner := range procOwners() {
		ownerPid, start, _ := strings.Cut(owner, ":")
		n, err := strconv.Atoi(ownerPid)
		if err != nil {
			continue
		}
		if cur, ok := procStart(n); ok && cur == start {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// startWatchdog starts a copy of this binary that waits for this process to
// die and then kills what it left. It learns of the death from its stdin: this
// process holds the only write end of that pipe and never closes it. It runs in
// its own session so that a signal to this process's group does not take it
// too, and it holds none of this process's output pipes, which `go test` waits
// on.
func startWatchdog() {
	r, w, err := os.Pipe()
	if err != nil {
		panic("conformance: negative control cannot start its watchdog: " + err.Error())
	}
	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), watchdogEnv+"="+ownerTag)
	c.Stdin = r
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		panic("conformance: negative control cannot start its watchdog: " + err.Error())
	}
	_ = r.Close()
	watchdogPipe = w
	go func() { _ = c.Wait() }()
}

// watchdogPipe is held open for the life of the process; see startWatchdog.
var watchdogPipe *os.File

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
	c.Env = append(append(os.Environ(), cmd.Env...), ownerEnv+"="+ownerTag)
	c.Dir = cmd.Dir
	c.Stdin = cmd.Stdin
	// Killing the direct process on cancellation reaches only this one pid.
	// badBackend leaking a backgrounded child is the correct, honest
	// behaviour of a backend with no isolation. Its own group keeps a signal
	// meant for the test binary's group away from it, so a property can
	// observe that leak; TestMain kills it afterwards by its ownerEnv mark.
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
	c.Env = append(append(os.Environ(), cmd.Env...), ownerEnv+"="+ownerTag)
	c.Dir = cmd.Dir
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.Start(); err != nil {
		return err
	}
	// Nobody else calls Wait, so this reaps the process once TestMain's
	// cleanup kills it, rather than leaving a zombie.
	go func() { _ = c.Wait() }()
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
