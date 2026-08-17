package docker

import (
	"bytes"
	"context"
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
	res, err := s.exec(ctx, cmd, "")
	s.touch(ctx)
	return res, err
}

// exec runs a command as user, without recording activity. Everything that
// records activity goes through Exec; this exists so touch itself does not
// recurse.
func (s *dockerSandbox) exec(ctx context.Context, cmd sandbox.Command, user string) (sandbox.Result, error) {
	if err := cmd.Validate(); err != nil {
		return sandbox.Result{}, err
	}

	timeout := s.resolveTimeout(cmd.Timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	execID, attached, err := s.attach(ctx, cmd, user)
	if err != nil {
		return sandbox.Result{}, err
	}
	defer attached.Close()

	if cmd.Stdin != nil {
		pumpStdin(attached, cmd.Stdin)
	}

	var stdout, stderr bytes.Buffer
	copyDone := make(chan error, 1)
	go func() {
		// The attach stream is multiplexed unless a TTY was allocated; StdCopy
		// splits it back into the two streams.
		_, err := stdcopy.StdCopy(&stdout, &stderr, attached.Reader)
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
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: inspect.ExitCode,
	}, nil
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
