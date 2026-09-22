package conformance

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

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

func (badSandbox) Exec(ctx context.Context, cmd sandbox.Command) (sandbox.Result, error) {
	if err := cmd.Validate(); err != nil {
		return sandbox.Result{}, err
	}
	c := exec.CommandContext(ctx, cmd.Argv[0], cmd.Argv[1:]...)
	c.Env = append(os.Environ(), cmd.Env...)
	c.Dir = cmd.Dir
	c.Stdin = cmd.Stdin

	stdout, err := c.Output()
	exitCode := 0
	var stderr []byte
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			stderr = exitErr.Stderr
		} else {
			return sandbox.Result{}, err
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
	return c.Start()
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
