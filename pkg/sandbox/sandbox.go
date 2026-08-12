package sandbox

import (
	"context"
	"io"
	"io/fs"
	"time"
)

// Backend provisions sandboxes on a host runtime. Implementations are safe for
// concurrent use.
type Backend interface {
	// Create returns a running sandbox for name, creating it if absent and
	// returning the existing one if present. It is the caller's session-affinity
	// primitive: the same name reaches the same sandbox until it is reaped.
	//
	// Options are applied only when the sandbox is created. Calling Create again
	// with different options on a live sandbox does not reconfigure it.
	Create(ctx context.Context, name string, opts ...CreateOption) (Sandbox, error)

	// Open returns an existing sandbox. It reports ErrNotFound if name has no
	// sandbox, and never creates one.
	Open(ctx context.Context, name string) (Sandbox, error)

	// List returns every sandbox this backend manages, running or stopped.
	List(ctx context.Context) ([]Info, error)

	// Destroy removes a sandbox and its writable layer. It is idempotent:
	// destroying an absent sandbox is not an error.
	Destroy(ctx context.Context, name string) error

	// Close releases the backend's own resources. It does not stop or destroy
	// running sandboxes, which outlive the process that created them.
	Close() error
}

// Sandbox is a live instance. Methods are safe for concurrent use, but the
// guest they talk to is not: concurrent Exec calls run concurrently inside it.
type Sandbox interface {
	// Info returns a snapshot of the sandbox's identity and state. It does not
	// query the runtime and so cannot fail; use [Backend.Open] for fresh state.
	Info() Info

	// Exec runs a command to completion and returns its output. A non-zero exit
	// status is reported in Result.ExitCode, not as an error — err is non-nil
	// only when the command could not be run or did not finish.
	Exec(ctx context.Context, cmd Command) (Result, error)

	// WriteFile writes src to path inside the sandbox, creating parent
	// directories as needed. It streams, so it is safe for large payloads.
	WriteFile(ctx context.Context, path string, mode fs.FileMode, src io.Reader) error

	// ReadFile opens path inside the sandbox for reading. The caller must close
	// the returned reader.
	ReadFile(ctx context.Context, path string) (io.ReadCloser, error)

	// StartProcess starts cmd as a detached background process under name. It is
	// idempotent: if a process is already running under name, it is left alone
	// and no error is returned.
	StartProcess(ctx context.Context, name string, cmd Command) error

	// Expose returns a signed, expiring URL for a port inside the sandbox.
	//
	// The returned token is a bearer credential and must be sent as a request
	// header, never a query parameter — query strings leak into access logs,
	// browser history, and Referer headers.
	Expose(ctx context.Context, port int, ttl time.Duration) (Preview, error)

	// Revoke invalidates a token returned by Expose before it expires.
	Revoke(ctx context.Context, port int, token string) error

	// Stop halts the sandbox without discarding it. A stopped sandbox can be
	// reached again through [Backend.Create] with the same name.
	Stop(ctx context.Context) error
}

// State is the lifecycle position of a sandbox.
//
// openblox deliberately models three states rather than tracking every
// transition: the container runtime is the authority, and a parallel state
// machine over it can only drift.
type State string

// The states a sandbox can be in.
const (
	// StateRunning means the sandbox is up and accepting commands.
	StateRunning State = "running"
	// StateStopped means the sandbox exists but is halted. It can be restarted
	// through [Backend.Create] with the same name.
	StateStopped State = "stopped"
	// StateError means the runtime reported a state openblox cannot act on. The
	// sandbox should be destroyed rather than reused.
	StateError State = "error"
)

// Info describes a sandbox.
type Info struct {
	// Name is the caller-supplied identity passed to Create.
	Name string
	// ID is the runtime's identifier, for correlating with host-level tooling.
	ID    string
	Image string
	State State

	CreatedAt time.Time
}

// Command is a program to run inside a sandbox.
//
// There is no "language" field. A sandbox runs commands; mapping a language to
// an interpreter invocation belongs to the caller, who knows what its image
// contains.
type Command struct {
	// Argv is the program and its arguments. It is executed directly, without a
	// shell, so no quoting or escaping is applied. To use shell syntax, invoke a
	// shell explicitly: []string{"sh", "-c", script}.
	Argv []string
	// Env entries are "KEY=value", merged over the sandbox's environment.
	Env []string
	// Dir is the working directory. Empty means the image's default.
	Dir   string
	Stdin io.Reader
	// Timeout bounds this command. Zero means the backend's default. The backend
	// clamps it to a configured maximum.
	Timeout time.Duration
}

// Validate reports whether the command is runnable.
func (c Command) Validate() error {
	if len(c.Argv) == 0 {
		return newInvalidError("command has no argv")
	}
	if c.Argv[0] == "" {
		return newInvalidError("command program is empty")
	}
	if c.Timeout < 0 {
		return newInvalidError("command timeout is negative")
	}
	for _, e := range c.Env {
		if !isEnvEntry(e) {
			return newInvalidError("environment entry %q is not KEY=value", e)
		}
	}
	return nil
}

// Result is the outcome of a completed command.
//
// Stdout and Stderr are bytes, not strings: a sandbox runs arbitrary programs
// and its output is not guaranteed to be valid UTF-8.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Preview is a signed, expiring route to a port inside a sandbox.
type Preview struct {
	URL   string
	Token string
	// Port is echoed back so a caller holding several previews can match them
	// up without tracking the mapping itself.
	Port      int
	ExpiresAt time.Time
}

// Expired reports whether the preview is no longer valid as of now.
func (p Preview) Expired(now time.Time) bool {
	return !now.Before(p.ExpiresAt)
}

func isEnvEntry(s string) bool {
	for i := range len(s) {
		if s[i] == '=' {
			return i > 0
		}
	}
	return false
}
