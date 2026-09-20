package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

type dockerSandbox struct {
	cli  *client.Client
	id   string
	info sandbox.Info

	defaultTimeout time.Duration
	maxTimeout     time.Duration

	// previews is nil unless the backend was configured with WithPreviews.
	previews *previews
}

func (s *dockerSandbox) Info() sandbox.Info { return s.info }

// Stop halts the sandbox without discarding it.
func (s *dockerSandbox) Stop(ctx context.Context) error {
	if err := s.cli.ContainerStop(ctx, s.id, container.StopOptions{}); err != nil {
		return fmt.Errorf("stop sandbox %q: %w", s.info.Name, err)
	}
	return nil
}

// resolveTimeout applies this sandbox's default and ceiling to a request.
func (s *dockerSandbox) resolveTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		requested = s.defaultTimeout
	}
	if s.maxTimeout > 0 && requested > s.maxTimeout {
		return s.maxTimeout
	}
	return requested
}

// Exec runs a command to completion inside the sandbox.
func (s *dockerSandbox) Exec(ctx context.Context, cmd sandbox.Command) (sandbox.Result, error) {
	res, err := s.exec(ctx, cmd, "", newPIDFile())
	s.touch(ctx)
	return res, err
}

// exec runs a command as user, without recording activity. Everything that
// records activity goes through Exec; this exists so touch itself does not
// recurse.
//
// A non-empty pidFile wraps the command so a timeout kills it; see killGroup.
// Only the caller's own commands pass one: openblox's bookkeeping is never
// killed on the word of a guest-writable file, and the kill is not itself
// wrapped.
func (s *dockerSandbox) exec(ctx context.Context, cmd sandbox.Command, user, pidFile string) (sandbox.Result, error) {
	if err := cmd.Validate(); err != nil {
		return sandbox.Result{}, err
	}

	timeout := s.resolveTimeout(cmd.Timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if pidFile != "" {
		cmd.Argv = append([]string{"sh", "-c", groupScript, "sh", pidFile}, cmd.Argv...)
	}

	execID, attached, err := s.attach(ctx, cmd, user)
	if err != nil {
		return sandbox.Result{}, err
	}
	defer attached.Close()

	if cmd.Stdin != nil {
		pumpStdin(attached, cmd.Stdin)
	}

	stdout := &cappedBuffer{limit: sandbox.MaxOutputBytes}
	stderr := &cappedBuffer{limit: sandbox.MaxOutputBytes}
	copyDone := make(chan error, 1)
	go func() {
		// The attach stream is multiplexed unless a TTY was allocated; StdCopy
		// splits it back into the two streams.
		_, err := stdcopy.StdCopy(stdout, stderr, attached.Reader)
		copyDone <- err
	}()

	select {
	case err := <-copyDone:
		if err != nil {
			return sandbox.Result{}, fmt.Errorf("read exec output in %q: %w", s.info.Name, err)
		}
	case <-ctx.Done():
		// The attach stream is a hijacked connection: cancelling the context does
		// not interrupt a blocked read on it. Closing the connection is what
		// unblocks StdCopy, so without this a timed-out command would still take
		// as long as the command itself.
		attached.Close()
		<-copyDone
		// Closing the stream does not stop the command, and Docker has no call
		// that kills an exec — so without this the command runs on, unobserved,
		// until the sandbox is reaped.
		if pidFile != "" {
			s.killGroup(context.WithoutCancel(ctx), pidFile)
		}
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return sandbox.Result{}, fmt.Errorf("command in %q: %w", s.info.Name, ctx.Err())
		}
		return sandbox.Result{}, fmt.Errorf("%w: command in %q exceeded %s", sandbox.ErrTimeout, s.info.Name, timeout)
	}

	// Inspect with a fresh context: the exec finished, and reusing an expired
	// one would turn a completed command into a spurious failure.
	inspectCtx, inspectCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer inspectCancel()

	inspect, err := s.cli.ContainerExecInspect(inspectCtx, execID)
	if err != nil {
		return sandbox.Result{}, fmt.Errorf("inspect exec in %q: %w", s.info.Name, err)
	}

	// A non-zero exit is the command's result, not our error.
	return sandbox.Result{
		Stdout:    stdout.buf.Bytes(),
		Stderr:    stderr.buf.Bytes(),
		ExitCode:  inspect.ExitCode,
		Truncated: stdout.truncated || stderr.truncated,
	}, nil
}

// groupScript records the process group a command runs in, then runs it.
//
// Under gVisor every exec starts a new session, so the wrapping shell is its own
// process-group leader and $$ names the whole group: the command and anything it
// starts, unless that deliberately calls setsid. (Under runc an exec does not
// start a session, and killScript falls back to killing the wrapper alone.)
//
// The command runs in a child so the record can be removed when it finishes,
// and its exit status is passed through unchanged. The child execs the command
// rather than letting the shell run it: `exec` always runs an external program,
// so argv[0] is never taken for a shell builtin (echo, kill, exit, test) and
// behaves exactly as it would without the wrapper. $1 is the record, everything
// after it the command, so no part of the command is parsed as shell syntax.
const groupScript = `f="$1"; shift; echo $$ >"$f" 2>/dev/null; (exec "$@"); s=$?; rm -f "$f"; exit $s`

// killScript kills the group recorded in $1. It runs as the sandbox user, so a
// forged record can only make it signal the guest's own processes.
//
// An absent or still-empty record exits killNoRecord so the caller can retry:
// it means the wrapper has not reached its first statement yet, which is not
// the same as having nothing to kill. The record is removed only once it has
// been read, so a concurrent write is never unlinked from under the wrapper.
const killScript = `read -r p <"$1" 2>/dev/null; case "$p" in "") exit 1;; esac; rm -f "$1"; case "$p" in *[!0-9]*|1) exit 0;; esac; kill -9 -"$p" 2>/dev/null || kill -9 "$p" 2>/dev/null; exit 0`

// killNoRecord is killScript's exit code for "the record is not there yet".
const killNoRecord = 1

// killTimeout bounds the kill itself, so a wedged sandbox cannot turn a timeout
// into a hang.
const killTimeout = 10 * time.Second

// killRecordWait bounds how long killGroup waits for a record to appear, and
// killRetryInterval how often it looks. The gap it covers is between Docker
// starting the exec and the wrapper's first statement — microseconds — so this
// is generous. It is spent only on the kill path, and only when there is no
// record: a command cancelled after it has written one is killed on the first
// attempt.
const (
	killRecordWait    = 2 * time.Second
	killRetryInterval = 50 * time.Millisecond
)

// newPIDFile names a per-exec record on the scratch tmpfs. Random, so
// concurrent execs never share one.
func newPIDFile() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "/tmp/.openblox-exec-" + hex.EncodeToString(b[:])
}

// killGroup kills a timed-out command and its process group.
//
// The record is written by the command's own wrapper, so a command cancelled in
// the moment between Docker starting the exec and that first statement has none
// yet. Giving up then would leave exactly the command a cancelling caller most
// expects to be gone — the one killed immediately, as when an openbloxd client
// disconnects — running until the sandbox is reaped, so killGroup waits briefly
// for the record to appear.
//
// Best effort even so, and only against code that is not trying to survive: a
// process that calls setsid, or a guest that fills /tmp so the record is never
// written, outlives it. Those are bounded by the sandbox's CPU and process caps
// and its lifetime, and ended by Destroy.
func (s *dockerSandbox) killGroup(ctx context.Context, pidFile string) {
	ctx, cancel := context.WithTimeout(ctx, killTimeout)
	defer cancel()

	deadline := time.Now().Add(killRecordWait)
	for {
		res, err := s.exec(ctx, sandbox.Command{
			Argv:    []string{"sh", "-c", killScript, "sh", pidFile},
			Timeout: killTimeout,
		}, "", "")
		if err != nil || res.ExitCode != killNoRecord || time.Now().After(deadline) {
			return
		}
		select {
		case <-time.After(killRetryInterval):
		case <-ctx.Done():
			return
		}
	}
}

// cappedBuffer keeps the first limit bytes written to it and discards the rest.
//
// It never reports an error for the excess: the stream is still drained, so the
// guest is not blocked on a full pipe and the command finishes with its real
// exit status. The buffer is a named field rather than embedded, so no promoted
// method (ReadFrom, WriteString) can write around the cap.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buf.Len(); len(p) > room {
		b.truncated = true
		_, _ = b.buf.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return b.buf.Write(p)
}

// attach starts an exec and hijacks its stream. user overrides the identity the
// command runs as; empty means the sandbox's own unprivileged user. It is never
// set from caller input — see touch for the only privileged use.
func (s *dockerSandbox) attach(ctx context.Context, cmd sandbox.Command, user string) (string, types.HijackedResponse, error) {
	created, err := s.cli.ContainerExecCreate(ctx, s.id, container.ExecOptions{
		Cmd:          cmd.Argv,
		Env:          cmd.Env,
		WorkingDir:   cmd.Dir,
		User:         user,
		AttachStdin:  cmd.Stdin != nil,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", types.HijackedResponse{}, fmt.Errorf("exec create in %q: %w", s.info.Name, err)
	}

	attached, err := s.cli.ContainerExecAttach(ctx, created.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", types.HijackedResponse{}, fmt.Errorf("exec attach in %q: %w", s.info.Name, err)
	}

	return created.ID, attached, nil
}

// pumpStdin feeds a command's stdin and half-closes it at EOF.
//
// It is separate from attach because not every attached stdin is a finite
// stream to be drained: a proxied connection keeps its inbound half open for the
// life of the connection and writes to it directly.
func pumpStdin(attached types.HijackedResponse, src io.Reader) {
	// Copy in the background: a guest that never reads stdin would otherwise
	// block us before the timeout could fire.
	go func() {
		defer func() { _ = attached.CloseWrite() }()
		_, _ = io.Copy(attached.Conn, src)
	}()
}

// WriteFile writes src to a path inside the sandbox, creating parent directories.
//
// This streams through exec rather than Docker's archive API. The archive API
// resolves paths against the container's image layers and cannot see tmpfs
// mounts — and openblox's writable scratch space is tmpfs, because
// container-layer disk quotas are unavailable on most hosts. So CopyToContainer
// reports "no such file" for a directory that demonstrably exists inside the
// sandbox. Exec sees the real mount namespace.
func (s *dockerSandbox) WriteFile(ctx context.Context, dest string, mode fs.FileMode, src io.Reader) error {
	if !path.IsAbs(dest) {
		return fmt.Errorf("%w: path %q is not absolute", sandbox.ErrInvalid, dest)
	}

	if err := s.run(ctx, "create directory", []string{"mkdir", "-p", path.Dir(dest)}); err != nil {
		return err
	}

	// The destination is passed as an argument, not interpolated into the shell
	// script, so it lands in $0 and cannot break out of the redirect. Building
	// `sh -c "cat > " + dest` instead would be a command injection on any caller
	// that accepts a path from its user.
	res, err := s.Exec(ctx, sandbox.Command{
		Argv:  []string{"sh", "-c", `cat > "$0"`, dest},
		Stdin: src,
	})
	if err != nil {
		return fmt.Errorf("write %q in %q: %w", dest, s.info.Name, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("write %q in %q: exit %d: %s",
			dest, s.info.Name, res.ExitCode, bytes.TrimSpace(res.Stderr))
	}

	return s.run(ctx, "set mode", []string{"chmod", fmt.Sprintf("%04o", mode.Perm()), dest})
}

// ReadFile opens a path inside the sandbox. The caller must close the reader.
//
// Like WriteFile, this goes through exec rather than the archive API, which
// cannot see the tmpfs scratch mounts.
func (s *dockerSandbox) ReadFile(ctx context.Context, src string) (io.ReadCloser, error) {
	if !path.IsAbs(src) {
		return nil, fmt.Errorf("%w: path %q is not absolute", sandbox.ErrInvalid, src)
	}

	// Probe first. The body is streamed, so a missing file would otherwise
	// surface as an empty read rather than an error the caller can act on.
	probe, err := s.Exec(ctx, sandbox.Command{Argv: []string{"test", "-f", src}})
	if err != nil {
		return nil, fmt.Errorf("stat %q in %q: %w", src, s.info.Name, err)
	}
	if probe.ExitCode != 0 {
		return nil, fmt.Errorf("%w: %q in sandbox %q", sandbox.ErrNotFound, src, s.info.Name)
	}

	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	_, attached, err := s.attach(streamCtx, sandbox.Command{Argv: []string{"cat", "--", src}}, "")
	if err != nil {
		cancel()
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		// stderr is discarded: the probe above already established the file is
		// readable, and a partial read surfaces as a short body.
		_, err := stdcopy.StdCopy(pw, io.Discard, attached.Reader)
		_ = pw.CloseWithError(err)
	}()

	return &execStream{Reader: pr, attached: attached, cancel: cancel}, nil
}

type execStream struct {
	io.Reader
	attached types.HijackedResponse
	cancel   context.CancelFunc
}

func (e *execStream) Close() error {
	e.attached.Close()
	e.cancel()
	return nil
}

// run executes a command and turns a non-zero exit into an error. For internal
// helpers a non-zero exit is a failure, unlike a caller's own command.
func (s *dockerSandbox) run(ctx context.Context, what string, argv []string) error {
	res, err := s.Exec(ctx, sandbox.Command{Argv: argv})
	if err != nil {
		return fmt.Errorf("%s in %q: %w", what, s.info.Name, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s in %q: exit %d: %s",
			what, s.info.Name, res.ExitCode, bytes.TrimSpace(res.Stderr))
	}
	return nil
}

func infoFrom(id string, labels map[string]string, image string, state *container.State) sandbox.Info {
	status := ""
	if state != nil {
		status = state.Status
	}
	return sandbox.Info{
		Name:      labels[labelName],
		ID:        id,
		Image:     image,
		State:     stateFromStatus(status),
		CreatedAt: parseTimeLabel(labels[labelCreatedAt]),
		Labels:    userLabels(labels),
	}
}

// Compile-time proof the Docker backend satisfies the contract.
var (
	_ sandbox.Backend = (*Backend)(nil)
	_ sandbox.Sandbox = (*dockerSandbox)(nil)
)
