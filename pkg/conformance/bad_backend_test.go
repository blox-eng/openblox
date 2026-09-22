package conformance

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// TestMain guarantees badSandbox's cleanup actually runs. reapGroup's delayed
// goroutine races the test binary's own exit: a fast run can finish and exit
// before that delay elapses, which would kill every pending goroutine —
// reapGroup's included — mid-sleep, leaking the very process it exists to
// clean up. This waits for every tracked process to be reaped, then sweeps
// for the one kind of leak reapGroup cannot reach at all, before the binary
// is allowed to exit.
func TestMain(m *testing.M) {
	code := m.Run()
	reapAllTracked()
	sweepDetachedMarkers()
	os.Exit(code)
}

// detachableMarkers are the process-lifecycle properties' own sleep markers
// (see process.go) that can end up running detached from any pgid badSandbox
// still has a handle to.
var detachableMarkers = []string{"3131", "3132", "3133", "3135", "3136", "3137"}

// sweepDetachedMarkers kills any leftover host process matching one of
// detachableMarkers by scanning /proc directly. It exists for
// propSetsidEscapesTheTimeoutKill: a setsid-detached process starts its own
// new session and process group, so it is not reachable by reapGroup's
// pgid-targeted kill — the same reason it survives openblox's own timeout
// kill in the real backend. This is a host-hygiene backstop run once after
// the whole suite, not a substitute for that property's own assertions,
// which have already run and recorded their result long before this fires.
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
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		line := string(cmdline)
		if !strings.Contains(line, "sleep") {
			continue
		}
		for _, m := range detachableMarkers {
			if strings.Contains(line, m) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				break
			}
		}
	}
}

var (
	trackedMu sync.Mutex
	tracked   []int
)

// trackForReap records pid so TestMain can guarantee it is killed even if
// reapGroup's own delayed goroutine never gets to run.
func trackForReap(pid int) {
	trackedMu.Lock()
	tracked = append(tracked, pid)
	trackedMu.Unlock()
}

func reapAllTracked() {
	trackedMu.Lock()
	defer trackedMu.Unlock()
	for _, pid := range tracked {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	tracked = nil
}

// badBackend is the negative control: it satisfies sandbox.Backend and
// isolates nothing, running every command directly on the host. Core must fail
// against it. It is test-only and must never be exported.
type badBackend struct{}

func newBadBackend(t *testing.T) sandbox.Backend {
	t.Helper()
	return badBackend{}
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

// reapDelay bounds how long a probe's process is allowed to linger on the
// host running the test after Exec or StartProcess returns. badSandbox
// deliberately does not stop what it starts on its own — a process or process
// group it leaked is exactly what the process-lifecycle properties must
// observe to correctly fail here — but a probe left entirely unreaped could
// hold a busy loop or a multi-minute sleep on the host for as long as it was
// written to run. Every property's own assertions run within a moment of the
// call that started the leak, so this delay is chosen to run comfortably
// after those assertions, never before them.
const reapDelay = 5 * time.Second

// reapGroup kills pid's whole process group after reapDelay. It exists only
// for host hygiene: it must never fire before a property has had the chance
// to observe what badSandbox leaked, or that observation — the entire point
// of the negative control for these properties — would be cut short.
func reapGroup(pid int) {
	trackForReap(pid)
	go func() {
		time.Sleep(reapDelay)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}()
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

	c := exec.Command(cmd.Argv[0], cmd.Argv[1:]...)
	c.Env = append(os.Environ(), cmd.Env...)
	c.Dir = cmd.Dir
	c.Stdin = cmd.Stdin
	// Grouped so a background child a probe starts ("cmd &") can be reaped by
	// pgid once the property is done observing it; see reapGroup. Killing the
	// direct process on cancellation still only reaches this one pid, not the
	// group — badBackend leaking a backgrounded child is the correct, honest
	// behaviour of a backend with no isolation, and reapGroup only cleans it
	// up after the fact.
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return err
}

func (badSandbox) ReadFile(_ context.Context, path string) (io.ReadCloser, error) {
	return os.Open(path)
}

func (badSandbox) StartProcess(_ context.Context, _ string, cmd sandbox.Command) error {
	c := exec.Command(cmd.Argv[0], cmd.Argv[1:]...)
	c.Env = append(os.Environ(), cmd.Env...)
	c.Dir = cmd.Dir
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.Start(); err != nil {
		return err
	}
	// badSandbox tracks nothing about a background process once started, the
	// same way it isolates nothing about it while running: nobody else calls
	// Wait, so this reaps it rather than leaving a zombie once reapGroup's
	// signal lands.
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
