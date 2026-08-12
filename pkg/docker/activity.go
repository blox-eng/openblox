package docker

import (
	"bytes"
	"context"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// touchTimeout bounds the bookkeeping write so a wedged sandbox cannot hold a
// goroutine open indefinitely.
const touchTimeout = 10 * time.Second

// touch records that the sandbox was used, for the reaper's idle bound.
//
// Docker exposes no "last exec" timestamp and container labels are immutable
// after create, so the timestamp has to live inside the sandbox. It is written
// to a root-owned tmpfs the unprivileged guest cannot modify, which is why this
// is the one exec openblox runs as root: without it, code in the sandbox could
// refresh its own idle deadline and never be reaped.
//
// The value written is the host's clock, not the guest's, so a sandbox with a
// skewed or deliberately altered clock cannot shift its own deadline either.
//
// Failures are ignored. Idle reaping is resource hygiene, and MaxAge is the
// bound that must hold regardless.
func (s *dockerSandbox) touch(ctx context.Context) {
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), touchTimeout)
		defer cancel()

		// The timestamp is passed as an argument, landing in $0, so it is never
		// interpreted as shell syntax.
		_, _ = s.exec(ctx, sandbox.Command{
			Argv:    []string{"sh", "-c", `echo "$0" > ` + lastUsedPath, time.Now().UTC().Format(time.RFC3339Nano)},
			Timeout: touchTimeout,
		}, rootUser)
	}()
}

// lastUsed reports when the sandbox last ran a command, or the zero time if that
// cannot be established — the sandbox is stopped, was never used, or predates
// activity tracking. Callers fall back to the creation time.
func (s *dockerSandbox) lastUsed(ctx context.Context) time.Time {
	res, err := s.exec(ctx, sandbox.Command{Argv: []string{"cat", lastUsedPath}}, "")
	if err != nil || res.ExitCode != 0 {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, string(bytes.TrimSpace(res.Stdout)))
	if err != nil {
		return time.Time{}
	}
	return t
}
