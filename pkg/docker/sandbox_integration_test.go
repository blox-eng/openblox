//go:build integration

package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func TestExecCapturesStdoutStderrAndExitCode(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-exec")
	ctx := context.Background()

	res, err := sb.Exec(ctx, sandbox.Command{
		Argv: []string{"sh", "-c", "echo out; echo err 1>&2; exit 3"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}

	if got := strings.TrimSpace(string(res.Stdout)); got != "out" {
		t.Errorf("stdout = %q, want %q", got, "out")
	}
	if got := strings.TrimSpace(string(res.Stderr)); got != "err" {
		t.Errorf("stderr = %q, want %q — streams are not demultiplexed", got, "err")
	}
	// A non-zero exit is the command's result, not a transport failure.
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.ExitCode)
	}
}

func TestExecRunsWithoutAShell(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-noshell")

	// Argv is executed directly, so shell metacharacters stay literal. If this
	// ever prints two lines, argv is reaching a shell and every caller passing
	// an untrusted path has an injection.
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"echo", "a; echo b"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "a; echo b" {
		t.Errorf("stdout = %q, want the literal argument — argv reached a shell", got)
	}
}

func TestExecHonoursTimeout(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-timeout")

	start := time.Now()
	_, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"sleep", "60"},
		Timeout: 2 * time.Second,
	})

	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("Exec = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("took %s to time out a 2s command", elapsed)
	}
}

func TestExecClampsTimeoutToCeiling(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-clamp",
		sandbox.WithCommandTimeouts(time.Second, 2*time.Second))

	// Requests an hour; the sandbox's ceiling is two seconds.
	start := time.Now()
	_, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"sleep", "60"},
		Timeout: time.Hour,
	})

	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("Exec = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("took %s; the requested hour was not clamped to the ceiling", elapsed)
	}
}

func TestExecStdin(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-stdin")

	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv:  []string{"cat"},
		Stdin: strings.NewReader("piped payload"),
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "piped payload" {
		t.Errorf("stdout = %q, want the piped payload", got)
	}
}

func TestExecRejectsInvalidCommand(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-badcmd")

	if _, err := sb.Exec(context.Background(), sandbox.Command{}); !errors.Is(err, sandbox.ErrInvalid) {
		t.Errorf("Exec with no argv = %v, want ErrInvalid", err)
	}
}

func TestFileRoundTrip(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-files")
	ctx := context.Background()

	want := []byte("line one\nline two\n")
	if err := sb.WriteFile(ctx, "/workspace/nested/dir/data.txt", 0o644, bytes.NewReader(want)); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	rc, err := sb.ReadFile(ctx, "/workspace/nested/dir/data.txt")
	if err != nil {
		t.Fatalf("ReadFile = %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round trip = %q, want %q", got, want)
	}
}

// Large enough to exercise the spool-and-stream path rather than a single
// buffer, without making the suite slow.
func TestWriteFileStreamsLargePayload(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-largefile")
	ctx := context.Background()

	const size = 8 << 20 // 8 MiB
	payload := bytes.Repeat([]byte("openblox"), size/8)

	if err := sb.WriteFile(ctx, "/workspace/big.bin", 0o644, bytes.NewReader(payload)); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"wc", "-c", "/workspace/big.bin"}})
	if err != nil {
		t.Fatalf("Exec wc = %v", err)
	}
	if !strings.Contains(string(res.Stdout), "8388608") {
		t.Errorf("size in sandbox = %q, want 8388608 bytes", strings.TrimSpace(string(res.Stdout)))
	}
}

func TestWriteFileRejectsRelativePath(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-relpath")

	err := sb.WriteFile(context.Background(), "relative/path.txt", 0o644, strings.NewReader("x"))
	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Errorf("WriteFile(relative) = %v, want ErrInvalid", err)
	}
}

func TestReadFileAbsentReportsNotFound(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-readmissing")

	_, err := sb.ReadFile(context.Background(), "/workspace/nope.txt")
	if !errors.Is(err, sandbox.ErrNotFound) {
		t.Errorf("ReadFile(absent) = %v, want ErrNotFound", err)
	}
}

// The root filesystem is read-only; only the scratch mounts accept writes.
func TestWritesOutsideScratchAreRejected(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-readonly")

	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c", "touch /etc/openblox-probe"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if res.ExitCode == 0 {
		t.Error("wrote to /etc; the root filesystem is not read-only")
	}
}
