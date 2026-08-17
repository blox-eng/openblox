# openbloxd Policy Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `openbloxd`, a daemon that owns the Docker connection and exposes only openblox's sandbox surface, so a caller never needs `/var/run/docker.sock`.

**Architecture:** The daemon reads named profiles from a config file and resolves each create request against one of them; no request field can reach `Spec.Runtime` or `Spec.Egress`. It listens on a Unix socket only. `pkg/brokerclient` implements the existing `sandbox.Backend` and `sandbox.Sandbox` interfaces plus `preview.Dialer`, so callers swap one constructor.

**Tech Stack:** Go 1.25.13, stdlib `net/http` over a Unix socket, `gopkg.in/yaml.v3` for config, existing `pkg/docker` backend underneath.

**Spec:** `specs/2026-08-15-openbloxd-policy-broker-design.md`

## Global Constraints

- Go 1.25.13 (`go.mod`). Do not raise or lower it.
- Repository is `github.com/blox-eng/openblox`.
- Exactly one new direct dependency is permitted: `gopkg.in/yaml.v3`. Add nothing else. The daemon holds root-equivalent Docker access, so its dependency tree stays minimal.
- `internal/` is for code outside the public contract. Daemon internals go there; anything a caller imports goes under `pkg/`.
- HTTP paths carry **no** version prefix. Not `/v1/sandboxes`, just `/sandboxes`.
- Every request body decoder MUST call `dec.DisallowUnknownFields()`. An unknown field is a 400, never an ignored field.
- Tests run with `make test` (`CGO_ENABLED=1 go test -race -cover ./...`). Integration tests are behind the `integration` build tag and run with `make test-integration`.
- Existing code style: comments explain *why*, never restate *what*. Match it.
- Error values come from `pkg/sandbox`: `ErrNotFound`, `ErrInvalid`, `ErrTimeout`, `ErrRuntimeUnavailable`, `ErrImageUnavailable`. Do not invent new sentinels outside the one this plan adds (`ErrProfileConflict`).

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `pkg/brokerapi/types.go` | Wire DTOs shared by daemon and client |
| `pkg/brokerapi/errors.go` | Error kind strings and status-code mapping, both directions |
| `internal/daemon/config.go` | Config and Profile types, loading, validation, `Profile.Options()` |
| `internal/daemon/listener.go` | Unix socket creation with mode and ownership enforcement |
| `internal/daemon/server.go` | Route table, strict decoding helpers, error responses |
| `internal/daemon/sandboxes.go` | create / get / list / stop / destroy handlers |
| `internal/daemon/exec.go` | exec / files / processes handlers |
| `internal/daemon/dial.go` | connection-upgrade handler for `DialPort` |
| `internal/daemon/reap.go` | periodic `Backend.Reap` ticker |
| `cmd/openbloxd/main.go` | Flags, wiring, signal handling |
| `pkg/brokerclient/client.go` | `sandbox.Backend` over the socket |
| `pkg/brokerclient/sandbox.go` | `sandbox.Sandbox` over the socket |
| `pkg/brokerclient/dial.go` | `DialPort` via connection upgrade |
| `pkg/brokerclient/options.go` | `WithProfile`, `WithPreviews`, policy-option rejection |
| `deploy/openbloxd.service` | systemd unit |
| `deploy/openbloxd.example.yaml` | Annotated reference config |

**Modified:**

| File | Change |
|---|---|
| `pkg/docker/image.go` | Registry auth on pull |
| `pkg/docker/backend.go` | `WithRegistryAuth` option |
| `ARCHITECTURE.md:43` | Amend the transport-wrapper rule |
| `Makefile` | `build-daemon` target |
| `docs/security.md` | Document the broker deployment |

---

### Task 1: Wire types and error mapping

**Files:**
- Create: `pkg/brokerapi/types.go`
- Create: `pkg/brokerapi/errors.go`
- Test: `pkg/brokerapi/errors_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `brokerapi.CreateRequest`, `brokerapi.Info`, `brokerapi.ExecRequest`, `brokerapi.ExecResponse`, `brokerapi.ProcessRequest`, `brokerapi.ProfileInfo`, `brokerapi.Error`; `brokerapi.KindOf(error) (kind string, status int)` and `brokerapi.ErrorFor(kind string) error`.

Why a `kind` string and not just the status code: `ErrRuntimeUnavailable` and `ErrImageUnavailable` would both be 503, and the client must map back to the exact sentinel so callers' `errors.Is` checks keep working.

- [ ] **Step 1: Write the failing test**

```go
package brokerapi

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func TestKindOfRoundTrips(t *testing.T) {
	cases := []struct {
		err    error
		kind   string
		status int
	}{
		{fmt.Errorf("%w: nope", sandbox.ErrNotFound), KindNotFound, http.StatusNotFound},
		{fmt.Errorf("%w: nope", sandbox.ErrInvalid), KindInvalid, http.StatusBadRequest},
		{fmt.Errorf("%w: nope", sandbox.ErrTimeout), KindTimeout, http.StatusGatewayTimeout},
		{fmt.Errorf("%w: nope", sandbox.ErrRuntimeUnavailable), KindRuntimeUnavailable, http.StatusServiceUnavailable},
		{fmt.Errorf("%w: nope", sandbox.ErrImageUnavailable), KindImageUnavailable, http.StatusServiceUnavailable},
		{errors.New("boom"), KindInternal, http.StatusInternalServerError},
	}
	for _, c := range cases {
		kind, status := KindOf(c.err)
		if kind != c.kind || status != c.status {
			t.Errorf("KindOf(%v) = %q/%d, want %q/%d", c.err, kind, status, c.kind, c.status)
		}
		if got := ErrorFor(kind); !errors.Is(got, sentinelFor(t, c.kind)) {
			t.Errorf("ErrorFor(%q) did not map back to the sentinel", kind)
		}
	}
}

func sentinelFor(t *testing.T, kind string) error {
	t.Helper()
	switch kind {
	case KindNotFound:
		return sandbox.ErrNotFound
	case KindInvalid:
		return sandbox.ErrInvalid
	case KindTimeout:
		return sandbox.ErrTimeout
	case KindRuntimeUnavailable:
		return sandbox.ErrRuntimeUnavailable
	case KindImageUnavailable:
		return sandbox.ErrImageUnavailable
	default:
		return ErrInternal
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/brokerapi/ -run TestKindOfRoundTrips -v`
Expected: FAIL — package does not compile, `KindOf` undefined.

- [ ] **Step 3: Write the implementation**

`pkg/brokerapi/types.go`:

```go
// Package brokerapi holds the wire types openbloxd speaks and brokerclient
// consumes. It deliberately mirrors pkg/sandbox rather than re-modelling it:
// the broker exposes the library's surface and nothing more.
package brokerapi

import "time"

// CreateRequest is the whole of what a caller may ask for. Every field that
// could weaken isolation is absent by design and is daemon configuration
// instead — see the profile config. Adding a field here is a security change.
type CreateRequest struct {
	Name    string            `json:"name"`
	Profile string            `json:"profile"`
	Env     []string          `json:"env,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// Info describes a sandbox. Profile is reported so a caller can tell which
// policy a pre-existing sandbox was created under.
type Info struct {
	Name      string    `json:"name"`
	ID        string    `json:"id"`
	Image     string    `json:"image"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	Profile   string    `json:"profile"`
}

// ExecRequest runs one command. Timeout is a Go duration string; the daemon
// clamps it to the profile's maximum, so it can only narrow.
type ExecRequest struct {
	Argv    []string `json:"argv"`
	Env     []string `json:"env,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	Timeout string   `json:"timeout,omitempty"`
}

// ExecResponse carries raw bytes: a sandbox runs arbitrary programs and its
// output is not guaranteed to be valid UTF-8.
type ExecResponse struct {
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// ProcessRequest starts a detached background process.
type ProcessRequest struct {
	Name string   `json:"name"`
	Argv []string `json:"argv"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
}

// ProfileInfo reports a profile's lifetime bounds. A caller running its own
// reaper needs these to stay ordered behind the daemon's.
type ProfileInfo struct {
	Name        string `json:"name"`
	IdleTimeout string `json:"idle_timeout"`
	MaxAge      string `json:"max_age"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Message string `json:"error"`
	Kind    string `json:"kind"`
}
```

`pkg/brokerapi/errors.go`:

```go
package brokerapi

import (
	"errors"
	"net/http"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Error kinds. The status code alone cannot distinguish every sentinel — two
// map to 503 — so the kind is what the client maps back from.
const (
	KindNotFound           = "not_found"
	KindInvalid            = "invalid"
	KindConflict           = "conflict"
	KindTimeout            = "timeout"
	KindRuntimeUnavailable = "runtime_unavailable"
	KindImageUnavailable   = "image_unavailable"
	KindInternal           = "internal"
)

// ErrProfileConflict means the named sandbox exists under a different profile.
// Returning the live sandbox instead would hand the caller a policy it did not
// ask for, which is exactly the confusion the broker exists to prevent.
var ErrProfileConflict = errors.New("sandbox exists under a different profile")

// ErrInternal is what an unrecognised server-side failure becomes on the
// client. The daemon's own message is logged, not returned: it would describe
// the host's internals to the caller.
var ErrInternal = errors.New("openbloxd: internal error")

// KindOf classifies err for the wire.
func KindOf(err error) (string, int) {
	switch {
	case errors.Is(err, sandbox.ErrNotFound):
		return KindNotFound, http.StatusNotFound
	case errors.Is(err, sandbox.ErrInvalid):
		return KindInvalid, http.StatusBadRequest
	case errors.Is(err, ErrProfileConflict):
		return KindConflict, http.StatusConflict
	case errors.Is(err, sandbox.ErrTimeout):
		return KindTimeout, http.StatusGatewayTimeout
	case errors.Is(err, sandbox.ErrRuntimeUnavailable):
		return KindRuntimeUnavailable, http.StatusServiceUnavailable
	case errors.Is(err, sandbox.ErrImageUnavailable):
		return KindImageUnavailable, http.StatusServiceUnavailable
	default:
		return KindInternal, http.StatusInternalServerError
	}
}

// ErrorFor maps a wire kind back to the sentinel, so a caller's errors.Is
// checks behave the same against the broker as against the library.
func ErrorFor(kind string) error {
	switch kind {
	case KindNotFound:
		return sandbox.ErrNotFound
	case KindInvalid:
		return sandbox.ErrInvalid
	case KindConflict:
		return ErrProfileConflict
	case KindTimeout:
		return sandbox.ErrTimeout
	case KindRuntimeUnavailable:
		return sandbox.ErrRuntimeUnavailable
	case KindImageUnavailable:
		return sandbox.ErrImageUnavailable
	default:
		return ErrInternal
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/brokerapi/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/brokerapi/
git commit -m "feat(brokerapi): wire types and error-kind mapping for openbloxd"
```

---

### Task 2: Profile configuration

**Files:**
- Create: `internal/daemon/config.go`
- Test: `internal/daemon/config_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: `sandbox.CreateOption`, `sandbox.Resources`, `sandbox.Lifetime`.
- Produces: `daemon.Config{Socket, SocketGroup, ReapInterval, Profiles map[string]Profile}`; `daemon.Profile` with method `Options() []sandbox.CreateOption`; `daemon.Load(path string) (*Config, error)`.

This is where the make-or-break rule lives. `Options()` is the *only* producer of `WithRuntime` and `WithEgress` anywhere in the daemon, and its input is a config file.

- [ ] **Step 1: Write the failing test**

```go
package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openbloxd.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadResolvesProfileIntoSpec(t *testing.T) {
	path := writeConfig(t, `
socket: /run/openbloxd/openbloxd.sock
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
    runtime: runsc
    egress: none
    user: "1000:1000"
    cpus: 2
    memory_mb: 2048
    disk_mb: 1024
    max_processes: 256
    idle_timeout: 30m
    max_age: 4h
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	spec := sandbox.NewSpec(cfg.Profiles["code-exec"].Options()...)
	if spec.Runtime != "runsc" || spec.Egress != sandbox.EgressNone {
		t.Errorf("spec runtime/egress = %q/%v", spec.Runtime, spec.Egress)
	}
	if spec.Resources.MemoryBytes != 2048<<20 || spec.Resources.DiskBytes != 1024<<20 {
		t.Errorf("resources = %+v", spec.Resources)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    privileged: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown profile field")
	}
}

func TestLoadRejectsDiskExceedingMemory(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    memory_mb: 512
    disk_mb: 1024
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: disk exceeds memory")
	}
}

func TestLoadRejectsNoProfiles(t *testing.T) {
	path := writeConfig(t, "socket: /tmp/s.sock\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: no profiles configured")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/daemon/ -v`
Expected: FAIL — `Load` undefined.

- [ ] **Step 3: Add the dependency and write the implementation**

```bash
go get gopkg.in/yaml.v3@v3.0.1
```

`internal/daemon/config.go`:

```go
// Package daemon implements openbloxd: the policy broker that owns the Docker
// connection so its callers need no socket access.
package daemon

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blox-eng/openblox/pkg/docker"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Config is the daemon's whole configuration.
type Config struct {
	Socket       string             `yaml:"socket"`
	SocketGroup  string             `yaml:"socket_group"`
	ReapInterval time.Duration      `yaml:"reap_interval"`
	Profiles     map[string]Profile `yaml:"profiles"`
}

// Profile is one named isolation policy. Every field here is deliberately
// unreachable from a request: this struct is the reason WithRuntime and
// WithEgress cannot be asked for over the wire.
type Profile struct {
	Image          string        `yaml:"image"`
	Runtime        string        `yaml:"runtime"`
	Egress         string        `yaml:"egress"`
	User           string        `yaml:"user"`
	CPUs           float64       `yaml:"cpus"`
	MemoryMB       int64         `yaml:"memory_mb"`
	DiskMB         int64         `yaml:"disk_mb"`
	MaxProcesses   int           `yaml:"max_processes"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxAge         time.Duration `yaml:"max_age"`
	DefaultTimeout time.Duration `yaml:"default_timeout"`
	MaxTimeout     time.Duration `yaml:"max_timeout"`
	RegistryAuth   *RegistryAuth `yaml:"registry_auth"`
}

// RegistryAuth authenticates image pulls. It lives here, and only here: the
// credentials never leave the daemon and are never a request field.
type RegistryAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Load reads and validates a config file.
//
// Decoding is strict. A misspelled key is a refusal to start rather than a
// silently unapplied bound, because an unapplied bound looks identical to a
// working one until something escapes.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Socket == "" {
		return fmt.Errorf("%w: socket path is empty", sandbox.ErrInvalid)
	}
	if len(c.Profiles) == 0 {
		return fmt.Errorf("%w: no profiles configured; the daemon would accept nothing", sandbox.ErrInvalid)
	}
	if c.ReapInterval == 0 {
		c.ReapInterval = time.Minute
	}
	for name, p := range c.Profiles {
		if err := p.validate(name); err != nil {
			return err
		}
	}
	return nil
}

func (p Profile) validate(name string) error {
	if p.Image == "" {
		return fmt.Errorf("%w: profile %q has no image", sandbox.ErrInvalid, name)
	}
	switch p.Egress {
	case "", "none", "unrestricted":
	default:
		return fmt.Errorf("%w: profile %q has egress %q, want none or unrestricted", sandbox.ErrInvalid, name, p.Egress)
	}
	if err := sandbox.NewSpec(p.Options()...).Resources.Validate(); err != nil {
		return fmt.Errorf("profile %q: %w", name, err)
	}
	return nil
}

// DigestPinned reports whether the profile's image is pinned by digest. The
// daemon warns rather than refuses: refusing would make a local tag-built image
// unusable in development, where there is no registry to pin against.
func (p Profile) DigestPinned() bool { return docker.IsDigestPinned(p.Image) }

// Options renders the profile as library options.
//
// This function is the only place in openbloxd that produces WithRuntime or
// WithEgress, and its sole input is the config file. Nothing derived from a
// request reaches it. Keep it that way.
func (p Profile) Options() []sandbox.CreateOption {
	opts := []sandbox.CreateOption{
		sandbox.WithImage(p.Image),
		sandbox.WithResources(sandbox.Resources{
			CPUs:         p.CPUs,
			MemoryBytes:  p.MemoryMB << 20,
			DiskBytes:    p.DiskMB << 20,
			MaxProcesses: p.MaxProcesses,
		}),
		sandbox.WithLifetime(sandbox.Lifetime{
			IdleTimeout: p.IdleTimeout,
			MaxAge:      p.MaxAge,
		}),
		sandbox.WithCommandTimeouts(p.DefaultTimeout, p.MaxTimeout),
	}
	if p.Runtime != "" {
		opts = append(opts, sandbox.WithRuntime(p.Runtime))
	}
	if p.User != "" {
		opts = append(opts, sandbox.WithUser(p.User))
	}
	if p.Egress == "unrestricted" {
		opts = append(opts, sandbox.WithEgress(sandbox.EgressUnrestricted))
	}
	return opts
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/daemon/ -v`
Expected: PASS, all four tests.

- [ ] **Step 5: Commit**

```bash
go mod tidy
git add go.mod go.sum internal/daemon/
git commit -m "feat(daemon): profile configuration, strictly decoded"
```

---

### Task 3: The socket listener

**Files:**
- Create: `internal/daemon/listener.go`
- Test: `internal/daemon/listener_test.go`

**Interfaces:**
- Consumes: `Config.Socket`, `Config.SocketGroup`.
- Produces: `daemon.Listen(socketPath, group string) (net.Listener, error)`.

A world-writable socket is the single way this design fails outright, so it must be impossible to reach by accident rather than merely discouraged.

- [ ] **Step 1: Write the failing test**

```go
package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListenCreatesSocketWithRestrictedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	ln, err := Listen(path, "")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket mode = %o, want 660", perm)
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(path, "")
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	_ = ln.Close()
}

func TestListenFailsOnUnknownGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	ln, err := Listen(path, "definitely-not-a-real-group")
	if err == nil {
		_ = ln.Close()
		t.Fatal("expected Listen to refuse an unresolvable group")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a refused Listen must not leave a socket behind")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/daemon/ -run TestListen -v`
Expected: FAIL — `Listen` undefined.

- [ ] **Step 3: Write the implementation**

`internal/daemon/listener.go`:

```go
package daemon

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
)

// socketMode is owner+group read/write and nothing for others. Access to this
// socket is access to sandbox creation, so the group is the whole ACL.
const socketMode = 0o660

// Listen creates the Unix socket the daemon serves on.
//
// It refuses to start rather than serve on a socket it could not lock down: a
// permissive socket is indistinguishable from a working one until something
// uses it, and by then the caller is trusting a boundary that is not there.
//
// A leftover socket from an unclean shutdown is removed first. Only a socket —
// removing anything else would let a misconfigured path delete a real file.
func Listen(socketPath, group string) (net.Listener, error) {
	if info, err := os.Stat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 && info.Size() > 0 {
			return nil, fmt.Errorf("refusing to replace %q: not a socket", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale socket %q: %w", socketPath, err)
		}
	}

	gid := -1
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return nil, fmt.Errorf("resolve socket group %q: %w", group, err)
		}
		if gid, err = strconv.Atoi(g.Gid); err != nil {
			return nil, fmt.Errorf("parse gid for group %q: %w", group, err)
		}
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", socketPath, err)
	}

	// Chmod after listen: the socket does not exist before it, and the umask
	// would otherwise decide the mode for us.
	if err := os.Chmod(socketPath, socketMode); err != nil {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("set mode on %q: %w", socketPath, err)
	}
	if gid >= 0 {
		if err := os.Chown(socketPath, -1, gid); err != nil {
			_ = ln.Close()
			_ = os.Remove(socketPath)
			return nil, fmt.Errorf("set group on %q: %w", socketPath, err)
		}
	}
	return ln, nil
}
```

Note the ordering in the failure paths: close the listener *and* remove the socket, so a refused start leaves nothing behind for the next attempt to trip over.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/daemon/ -run TestListen -v`
Expected: PASS, all three.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/listener.go internal/daemon/listener_test.go
git commit -m "feat(daemon): socket listener that refuses to start unlocked"
```

---

### Task 4: Server skeleton, strict decoding, error responses

**Files:**
- Create: `internal/daemon/server.go`
- Test: `internal/daemon/server_test.go`

**Interfaces:**
- Consumes: `Config`, `brokerapi` types and kinds.
- Produces: `daemon.New(backend Backend, cfg *Config) *Server`; `(*Server).Handler() http.Handler`; the `daemon.Backend` interface (`sandbox.Backend` plus `DialPort` and `Reap`); helpers `decode[T any](w, r) (T, bool)` and `fail(w, err)`.

`Backend` is declared as an interface here, not as `*docker.Backend`, so every handler test runs against a fake and the whole suite stays unit-speed.

- [ ] **Step 1: Write the failing test**

```go
package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/brokerapi"
)

func TestUnknownFieldIsRejected(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec","runtime":"runc"}`))

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body brokerapi.Error
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != brokerapi.KindInvalid {
		t.Errorf("kind = %q, want %q", body.Kind, brokerapi.KindInvalid)
	}
	if !strings.Contains(body.Message, "runtime") {
		t.Errorf("message %q should name the offending field", body.Message)
	}
}

func TestInternalErrorDetailIsNotReturned(t *testing.T) {
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).createErr = errStub("secret host path /var/lib/docker")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/var/lib/docker") {
		t.Error("internal detail leaked into the response body")
	}
}
```

Add the fake and helper in the same file:

```go
type errStub string

func (e errStub) Error() string { return string(e) }

type fakeBackend struct {
	sandbox.Backend
	createErr error
	created   map[string]sandbox.Spec
}

func (f *fakeBackend) Create(ctx context.Context, name string, opts ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.created == nil {
		f.created = map[string]sandbox.Spec{}
	}
	f.created[name] = sandbox.NewSpec(opts...)
	return nil, sandbox.ErrNotFound // handlers under test re-Open; see Task 5
}

func (f *fakeBackend) DialPort(context.Context, string, int) (net.Conn, error) { return nil, nil }
func (f *fakeBackend) Reap(context.Context) ([]string, error)                  { return nil, nil }

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &Config{
		Socket: "/tmp/unused.sock",
		Profiles: map[string]Profile{
			"code-exec": {Image: "example.com/i@sha256:abc", Runtime: "runsc", MemoryMB: 2048, DiskMB: 1024},
		},
	}
	return New(&fakeBackend{}, cfg)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/daemon/ -run 'TestUnknownField|TestInternalError' -v`
Expected: FAIL — `New` undefined.

- [ ] **Step 3: Write the implementation**

`internal/daemon/server.go`:

```go
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Backend is what the daemon needs from a provisioner: the library contract
// plus the two methods outside it that the broker exposes.
type Backend interface {
	sandbox.Backend
	DialPort(ctx context.Context, name string, port int) (net.Conn, error)
	Reap(ctx context.Context) ([]string, error)
}

// Server routes broker requests onto a Backend under a fixed policy.
type Server struct {
	backend Backend
	cfg     *Config
}

// New returns a Server. It does not listen; see Listen and Handler.
func New(backend Backend, cfg *Config) *Server {
	return &Server{backend: backend, cfg: cfg}
}

// Handler returns the route table.
//
// No path carries a version prefix: the daemon and its client ship together and
// speak over a local socket, so there is no independently versioned consumer to
// protect. A header can version this later without a guess baked into a path.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sandboxes", s.handleCreate)
	mux.HandleFunc("GET /sandboxes", s.handleList)
	mux.HandleFunc("GET /sandboxes/{name}", s.handleGet)
	mux.HandleFunc("DELETE /sandboxes/{name}", s.handleDestroy)
	mux.HandleFunc("POST /sandboxes/{name}/stop", s.handleStop)
	mux.HandleFunc("POST /sandboxes/{name}/exec", s.handleExec)
	mux.HandleFunc("PUT /sandboxes/{name}/files/{path...}", s.handleWriteFile)
	mux.HandleFunc("GET /sandboxes/{name}/files/{path...}", s.handleReadFile)
	mux.HandleFunc("POST /sandboxes/{name}/processes", s.handleStartProcess)
	mux.HandleFunc("GET /sandboxes/{name}/dial/{port}", s.handleDial)
	mux.HandleFunc("GET /profiles", s.handleProfiles)
	return mux
}

// decode reads a strict JSON body. An unknown field is a 400 and not an
// ignored field: silently accepting one is how a request field that must not
// exist comes back, because the caller looks like it is being obeyed.
func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		fail(w, fmt.Errorf("%w: %s", sandbox.ErrInvalid, err.Error()))
		return v, false
	}
	return v, true
}

// respond writes a JSON body with the given status.
func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// fail classifies err and answers with it.
//
// An unrecognised error is logged in full and reported as a bare "internal
// error". The detail would describe the host's internals to whoever is holding
// the socket, which is the same discipline preview.proxyError follows.
func fail(w http.ResponseWriter, err error) {
	kind, status := brokerapi.KindOf(err)
	message := err.Error()
	if kind == brokerapi.KindInternal {
		slog.Error("openbloxd request failed", slog.Any("error", err))
		message = "internal error"
	}
	respond(w, status, brokerapi.Error{Message: message, Kind: kind})
}

var _ = errors.Is // retained for handlers added in later tasks
```

Add `"fmt"` to the import block. Remove the `var _ = errors.Is` line once Task 5 uses `errors.Is` directly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/daemon/ -v`
Expected: PASS. Handlers not yet written will fail to compile — write them as no-op stubs returning `fail(w, sandbox.ErrNotFound)` for now; Tasks 5–7 replace each.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/server.go internal/daemon/server_test.go
git commit -m "feat(daemon): server skeleton with strict decoding and error mapping"
```

---

### Task 5: Sandbox lifecycle handlers and the profile invariant

**Files:**
- Create: `internal/daemon/sandboxes.go`
- Test: `internal/daemon/sandboxes_test.go`

**Interfaces:**
- Consumes: `Server`, `Config.Profiles`, `brokerapi.CreateRequest`, `brokerapi.Info`.
- Produces: handlers `handleCreate`, `handleGet`, `handleList`, `handleDestroy`, `handleStop`; the profile label constant `labelProfile = "openbloxd.profile"`.

The profile is recorded as a sandbox label so a later `Create` can detect a mismatch. Without it, asking for `browser` on a name that already exists as `code-exec` silently returns the wrong policy — `Backend.Create` returns the live sandbox when the name exists.

- [ ] **Step 1: Write the failing test**

```go
func TestCreateAppliesProfilePolicy(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	spec := fake.created["a"]
	if spec.Runtime != "runsc" {
		t.Errorf("runtime = %q, want runsc from the profile", spec.Runtime)
	}
	if spec.Egress != sandbox.EgressNone {
		t.Errorf("egress = %v, want none", spec.Egress)
	}
	if spec.Image != "example.com/i@sha256:abc" {
		t.Errorf("image = %q, want the profile's", spec.Image)
	}
}

func TestCreateRejectsUnknownProfile(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"nope"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCreateOnExistingNameWithDifferentProfileConflicts(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "browser"} // name -> profile label

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestCreateRequiresName(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
```

Extend `fakeBackend` with `existing map[string]string` and an `Open` that returns a fake sandbox carrying the recorded profile label, plus `List` returning one `sandbox.Info` per entry.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/daemon/ -run TestCreate -v`
Expected: FAIL — handlers are stubs, statuses are 404.

- [ ] **Step 3: Write the implementation**

`internal/daemon/sandboxes.go`:

```go
package daemon

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// labelProfile records which policy a sandbox was created under, so a later
// Create under a different profile can be refused rather than silently served
// the existing sandbox.
const labelProfile = "openbloxd.profile"

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[brokerapi.CreateRequest](w, r)
	if !ok {
		return
	}
	if req.Name == "" {
		fail(w, fmt.Errorf("%w: name is empty", sandbox.ErrInvalid))
		return
	}
	profile, ok := s.cfg.Profiles[req.Profile]
	if !ok {
		fail(w, fmt.Errorf("%w: no profile named %q", sandbox.ErrInvalid, req.Profile))
		return
	}

	// Refuse before creating: an existing sandbox under another profile must not
	// be handed back as though it satisfied this request.
	if existing, err := s.backend.Open(r.Context(), req.Name); err == nil {
		if got := existing.Info().Labels[labelProfile]; got != req.Profile {
			fail(w, fmt.Errorf("%w: %q exists under profile %q, requested %q",
				brokerapi.ErrProfileConflict, req.Name, got, req.Profile))
			return
		}
	} else if !errors.Is(err, sandbox.ErrNotFound) {
		fail(w, err)
		return
	}

	// Profile options first, caller options second — and the caller's are only
	// ever env and labels. Nothing here can reach Runtime or Egress.
	opts := profile.Options()
	opts = append(opts, sandbox.WithLabel(labelProfile, req.Profile))
	if len(req.Env) > 0 {
		opts = append(opts, sandbox.WithEnv(req.Env...))
	}
	for k, v := range req.Labels {
		if k == labelProfile {
			fail(w, fmt.Errorf("%w: label %q is reserved", sandbox.ErrInvalid, labelProfile))
			return
		}
		opts = append(opts, sandbox.WithLabel(k, v))
	}

	sb, err := s.backend.Create(r.Context(), req.Name, opts...)
	if err != nil {
		fail(w, err)
		return
	}
	respond(w, http.StatusCreated, infoOf(sb.Info(), req.Profile))
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	info := sb.Info()
	respond(w, http.StatusOK, infoOf(info, info.Labels[labelProfile]))
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	all, err := s.backend.List(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]brokerapi.Info, 0, len(all))
	for _, i := range all {
		out = append(out, infoOf(i, i.Labels[labelProfile]))
	}
	respond(w, http.StatusOK, out)
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.Destroy(r.Context(), r.PathValue("name")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	if err := sb.Stop(r.Context()); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func infoOf(i sandbox.Info, profile string) brokerapi.Info {
	return brokerapi.Info{
		Name:      i.Name,
		ID:        i.ID,
		Image:     i.Image,
		State:     string(i.State),
		CreatedAt: i.CreatedAt,
		Profile:   profile,
	}
}
```

**`sandbox.Info` has no `Labels` field today.** Add one, since the daemon needs to read back the profile it recorded and `Info` is the only thing `Sandbox.Info()` returns:

In `pkg/sandbox/sandbox.go`, add to `Info`:

```go
	// Labels are the caller's own labels, as passed to WithLabel. Backends
	// strip their internal bookkeeping; what appears here is what was set.
	Labels map[string]string
```

In `pkg/docker/backend.go`, populate it in `infoFrom` and in `List` by collecting keys carrying `labelUserPfx` and trimming the prefix.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/daemon/ ./pkg/docker/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/sandboxes.go internal/daemon/sandboxes_test.go pkg/sandbox/sandbox.go pkg/docker/backend.go
git commit -m "feat(daemon): lifecycle handlers with the profile-conflict invariant"
```

---

### Task 6: Exec, files and process handlers

**Files:**
- Create: `internal/daemon/exec.go`
- Test: `internal/daemon/exec_test.go`

**Interfaces:**
- Consumes: `Server`, `brokerapi.ExecRequest/ExecResponse/ProcessRequest`.
- Produces: handlers `handleExec`, `handleReadFile`, `handleWriteFile`, `handleStartProcess`.

Files stream in both directions: the request body *is* the content on write, the response body *is* the content on read. Do not buffer — a sandbox payload can be large.

- [ ] **Step 1: Write the failing test**

```go
func TestExecPassesArgvAndClampedTimeout(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/a/exec",
		strings.NewReader(`{"argv":["echo","hi"],"timeout":"5s"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if got := fake.lastCommand.Argv; len(got) != 2 || got[0] != "echo" {
		t.Errorf("argv = %v", got)
	}
	if fake.lastCommand.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", fake.lastCommand.Timeout)
	}
}

func TestExecRejectsBadTimeoutString(t *testing.T) {
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/a/exec",
		strings.NewReader(`{"argv":["echo"],"timeout":"soon"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestWriteFileStreamsBodyToSandbox(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sandboxes/a/files/workspace/main.go",
		strings.NewReader("package main"))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body)
	}
	if fake.written["/workspace/main.go"] != "package main" {
		t.Errorf("written = %q", fake.written["/workspace/main.go"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/daemon/ -run 'TestExec|TestWriteFile' -v`
Expected: FAIL — stub handlers return 404.

- [ ] **Step 3: Write the implementation**

`internal/daemon/exec.go`:

```go
package daemon

import (
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"time"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// filePerm is the mode written files get. The sandbox runs unprivileged and
// every writable mount is noexec, so this is ordinary read/write.
const filePerm fs.FileMode = 0o644

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[brokerapi.ExecRequest](w, r)
	if !ok {
		return
	}
	var timeout time.Duration
	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil {
			fail(w, fmt.Errorf("%w: timeout %q: %s", sandbox.ErrInvalid, req.Timeout, err))
			return
		}
		timeout = d
	}

	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}

	// The sandbox clamps the timeout to the profile's ceiling through the
	// library's ResolveTimeout, so a caller can only narrow it.
	res, err := sb.Exec(r.Context(), sandbox.Command{
		Argv:    req.Argv,
		Env:     req.Env,
		Dir:     req.Dir,
		Timeout: timeout,
	})
	if err != nil {
		fail(w, err)
		return
	}
	respond(w, http.StatusOK, brokerapi.ExecResponse{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: res.ExitCode,
	})
}

func (s *Server) handleWriteFile(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	// Stream the body straight through: a sandbox payload can be large, and
	// buffering it here would put the caller's file in the daemon's heap.
	if err := sb.WriteFile(r.Context(), "/"+r.PathValue("path"), filePerm, r.Body); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReadFile(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	rc, err := sb.ReadFile(r.Context(), "/"+r.PathValue("path"))
	if err != nil {
		fail(w, err)
		return
	}
	defer func() { _ = rc.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	// An error partway through cannot change the status: it is already sent.
	// Log it and drop the connection rather than append a lie to the body.
	if _, err := io.Copy(w, rc); err != nil {
		slog.Warn("openbloxd: read-file stream truncated", slog.Any("error", err))
	}
}

func (s *Server) handleStartProcess(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[brokerapi.ProcessRequest](w, r)
	if !ok {
		return
	}
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	err = sb.StartProcess(r.Context(), req.Name, sandbox.Command{
		Argv: req.Argv,
		Env:  req.Env,
		Dir:  req.Dir,
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

Add `"log/slog"` to the imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/daemon/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/exec.go internal/daemon/exec_test.go
git commit -m "feat(daemon): exec, file and process handlers"
```

---

### Task 7: The dial upgrade, profiles endpoint and reaper

**Files:**
- Create: `internal/daemon/dial.go`
- Create: `internal/daemon/reap.go`
- Test: `internal/daemon/dial_test.go`

**Interfaces:**
- Consumes: `Backend.DialPort`, `Backend.Reap`, `Config.Profiles`, `Config.ReapInterval`.
- Produces: handlers `handleDial`, `handleProfiles`; `(*Server).RunReaper(ctx context.Context)`.

`DialPort` is the daemon's entire involvement in previews. `Expose` and `Revoke` have no endpoint: they only sign, so the client does them locally and the daemon holds no signing key.

Nothing calls `Backend.Reap` today, so openblox's idle and max-age labels are currently written and never enforced. The daemon owns lifetime, so it runs the sweep.

- [ ] **Step 1: Write the failing test**

```go
func TestDialUpgradesAndCopiesBothWays(t *testing.T) {
	client, server := net.Pipe()
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).conn = server
	srv.backend.(*fakeBackend).existing = map[string]string{"a": "code-exec"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = http.Serve(ln, srv.Handler()) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	fmt.Fprintf(conn, "GET /sandboxes/a/dial/8080 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: openblox-stream\r\n\r\n")

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status line = %q, want 101", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	go func() { _, _ = client.Write([]byte("from-sandbox")) }()
	buf := make([]byte, len("from-sandbox"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "from-sandbox" {
		t.Errorf("read %q", buf)
	}
}

func TestProfilesReportsLifetimeBounds(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/profiles", nil))

	var out []brokerapi.ProfileInfo
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Name != "code-exec" {
		t.Fatalf("profiles = %+v", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/daemon/ -run 'TestDial|TestProfiles' -v`
Expected: FAIL — stubs.

- [ ] **Step 3: Write the implementation**

`internal/daemon/dial.go`:

```go
package daemon

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// upgradeProto names the raw stream this handler switches to. It is not a
// WebSocket: there is no framing, because the payload is an arbitrary byte
// stream that both sides already know how to interpret.
const upgradeProto = "openblox-stream"

// handleDial hands the caller a raw stream to a port inside the sandbox.
//
// This is the whole of the daemon's role in previews. The preview handler
// itself runs in the caller, which needs only a byte stream and no Docker
// access, so the browser-facing surface stays out of the process that holds
// the socket.
func (s *Server) handleDial(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		fail(w, fmt.Errorf("%w: port %q is not in 1-65535", sandbox.ErrInvalid, r.PathValue("port")))
		return
	}

	upstream, err := s.backend.DialPort(r.Context(), r.PathValue("name"), port)
	if err != nil {
		fail(w, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	rc := http.NewResponseController(w)
	downstream, buf, err := rc.Hijack()
	if err != nil {
		fail(w, fmt.Errorf("%w: connection cannot be hijacked: %s", sandbox.ErrInvalid, err))
		return
	}
	defer func() { _ = downstream.Close() }()

	if _, err := io.WriteString(downstream,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+upgradeProto+"\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}

	// Anything the client pipelined behind the request line is already in the
	// reader and would be lost if we read from the socket directly.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, buf)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(downstream, upstream)
	}()
	wg.Wait()
}

func (s *Server) handleProfiles(w http.ResponseWriter, _ *http.Request) {
	out := make([]brokerapi.ProfileInfo, 0, len(s.cfg.Profiles))
	for name, p := range s.cfg.Profiles {
		out = append(out, brokerapi.ProfileInfo{
			Name:        name,
			IdleTimeout: p.IdleTimeout.String(),
			MaxAge:      p.MaxAge.String(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	respond(w, http.StatusOK, out)
}
```

Add `"sort"` to the imports.

`internal/daemon/reap.go`:

```go
package daemon

import (
	"context"
	"log/slog"
	"time"
)

// RunReaper sweeps expired sandboxes until ctx is cancelled.
//
// The daemon owns lifetime now, so it owns the sweep. Nothing ran this before:
// the library wrote idle and max-age labels that no process acted on, so a
// sandbox whose caller vanished lived until someone noticed.
func (s *Server) RunReaper(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reaped, err := s.backend.Reap(ctx)
			if err != nil {
				slog.Warn("openbloxd: reap sweep failed", slog.Any("error", err))
				continue
			}
			for _, name := range reaped {
				slog.Info("openbloxd: reaped expired sandbox", slog.String("sandbox", name))
			}
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/daemon/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/dial.go internal/daemon/reap.go internal/daemon/dial_test.go
git commit -m "feat(daemon): dial upgrade, profiles endpoint and the reaper sweep"
```

---

### Task 8: Registry auth in the library

**Files:**
- Modify: `pkg/docker/image.go:25-51`
- Modify: `pkg/docker/backend.go:59-88`
- Test: `pkg/docker/image_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `docker.WithRegistryAuth(username, password string) Option`.

openblox's `ImagePull` sends no auth today, so a private image must already be in the local store. The broker is where this belongs: credentials live in the daemon's config and are never a request field.

- [ ] **Step 1: Write the failing test**

```go
func TestRegistryAuthEncodesAsDockerExpects(t *testing.T) {
	b := &Backend{}
	if err := WithRegistryAuth("alice", "s3cret")(b); err != nil {
		t.Fatal(err)
	}
	if b.registryAuth == "" {
		t.Fatal("registryAuth is empty")
	}
	raw, err := base64.URLEncoding.DecodeString(b.registryAuth)
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	var got registry.AuthConfig
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" || got.Password != "s3cret" {
		t.Errorf("decoded = %+v", got)
	}
}

func TestRegistryAuthRejectsEmptyUsername(t *testing.T) {
	b := &Backend{}
	if err := WithRegistryAuth("", "s3cret")(b); err == nil {
		t.Fatal("expected an error for an empty username")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/docker/ -run TestRegistryAuth -v`
Expected: FAIL — `WithRegistryAuth` undefined.

- [ ] **Step 3: Write the implementation**

In `pkg/docker/backend.go`, add the field to `Backend`:

```go
	// registryAuth is the base64url X-Registry-Auth value used when pulling.
	// Empty means anonymous, which is what openblox did before this existed.
	registryAuth string
```

And the option:

```go
// WithRegistryAuth authenticates image pulls.
//
// Without it a private image must already be present in the local store,
// because openblox pulls anonymously. Credentials given here stay in this
// process: they are sent to the daemon on pull and never recorded on the
// sandbox, whose labels are visible to anything with daemon access.
func WithRegistryAuth(username, password string) Option {
	return func(b *Backend) error {
		if username == "" {
			return fmt.Errorf("%w: registry username is empty", sandbox.ErrInvalid)
		}
		blob, err := json.Marshal(registry.AuthConfig{Username: username, Password: password})
		if err != nil {
			return fmt.Errorf("encode registry auth: %w", err)
		}
		b.registryAuth = base64.URLEncoding.EncodeToString(blob)
		return nil
	}
}
```

Imports to add in `backend.go`: `encoding/base64`, `encoding/json`, `github.com/docker/docker/api/types/registry`.

In `pkg/docker/image.go:32`, pass it through:

```go
	body, err := b.cli.ImagePull(ctx, ref, image.PullOptions{RegistryAuth: b.registryAuth})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/docker/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/docker/backend.go pkg/docker/image.go pkg/docker/image_test.go
git commit -m "feat(docker): authenticate image pulls with WithRegistryAuth"
```

---

### Task 9: The daemon binary

**Files:**
- Create: `cmd/openbloxd/main.go`
- Create: `deploy/openbloxd.service`
- Create: `deploy/openbloxd.example.yaml`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `daemon.Load`, `daemon.Listen`, `daemon.New`, `(*Server).Handler`, `(*Server).RunReaper`, `docker.New`, `docker.WithRegistryAuth`.
- Produces: the `openbloxd` binary.

A tag-pinned image logs a warning at startup. Warn rather than refuse: refusing would make a locally built image unusable in development, where there is no registry to pin against.

- [ ] **Step 1: Write the code**

`cmd/openbloxd/main.go`:

```go
// Command openbloxd brokers the Docker API so callers never need socket access.
//
// It owns the Docker connection and exposes only openblox's own surface, under
// a policy read from its config file. A caller that is compromised can create
// sandboxes, which it can do by design; it cannot mount the host filesystem or
// start a privileged container.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blox-eng/openblox/internal/daemon"
	"github.com/blox-eng/openblox/pkg/docker"
)

func main() {
	configPath := flag.String("config", "/etc/openbloxd/config.yaml", "path to the config file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		slog.Error("openbloxd: exiting", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := daemon.Load(configPath)
	if err != nil {
		return err
	}

	var opts []docker.Option
	for name, p := range cfg.Profiles {
		if !p.DigestPinned() {
			slog.Warn("profile image is not pinned to a digest; whoever controls the registry can repoint the tag",
				slog.String("profile", name), slog.String("image", p.Image))
		}
		if p.RegistryAuth != nil {
			opts = append(opts, docker.WithRegistryAuth(p.RegistryAuth.Username, p.RegistryAuth.Password))
		}
	}

	backend, err := docker.New(opts...)
	if err != nil {
		return err
	}
	defer func() { _ = backend.Close() }()

	ln, err := daemon.Listen(cfg.Socket, cfg.SocketGroup)
	if err != nil {
		return err
	}

	srv := daemon.New(backend, cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go srv.RunReaper(ctx)

	// No read or write timeout: exec can legitimately run for minutes and a
	// dialled preview stream is open for as long as the page is. The library's
	// own command timeouts are the bound that applies here.
	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("openbloxd listening", slog.String("socket", cfg.Socket), slog.Int("profiles", len(cfg.Profiles)))
	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
```

**Only one registry credential is supported across all profiles**, because `docker.Option` configures the `Backend` rather than a single pull. If two profiles ever need different registries, the option has to move onto the create path — note it and leave it; a second registry is not a requirement today.

`deploy/openbloxd.service`:

```ini
[Unit]
Description=openbloxd sandbox policy broker
After=docker.service
Requires=docker.service

[Service]
Type=exec
ExecStart=/usr/local/bin/openbloxd --config /etc/openbloxd/config.yaml
User=openbloxd
# The Docker socket is the daemon's whole privilege. It holds it so nothing
# else has to.
SupplementaryGroups=docker
RuntimeDirectory=openbloxd
RuntimeDirectoryMode=0750
Restart=on-failure

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`deploy/openbloxd.example.yaml`:

```yaml
# openbloxd reference configuration.
#
# Everything that could weaken a sandbox's isolation is here and nowhere else.
# No request field maps to any of it: a request naming one is rejected.

socket: /run/openbloxd/openbloxd.sock
# The group that may reach the socket. This is the whole access control list:
# membership grants sandbox creation.
socket_group: openbloxd
reap_interval: 1m

profiles:
  code-exec:
    # Pin a digest. A tag can be repointed by whoever controls the registry,
    # and the image is the sandbox's entire userland.
    image: ghcr.io/blox-eng/blox-sandbox@sha256:CHANGEME
    runtime: runsc          # gVisor. Anything else trades away the isolation.
    egress: none            # No interface at all: no resolver, no route.
    user: "1000:1000"
    cpus: 2
    memory_mb: 2048
    disk_mb: 1024           # tmpfs, drawn from memory; must not exceed it.
    max_processes: 256      # Without this a fork bomb exhausts host PIDs.
    idle_timeout: 30m
    max_age: 4h
    default_timeout: 60s
    max_timeout: 10m

  browser:
    image: ghcr.io/blox-eng/blox-browser@sha256:CHANGEME
    runtime: runsc
    egress: none
    user: "1000:1000"
    cpus: 2
    memory_mb: 4096
    disk_mb: 2048
    max_processes: 256
    idle_timeout: 30m
    max_age: 4h
```

Add to the `Makefile`, and extend the `.PHONY` line with `build-daemon`:

```make
build-daemon:
	CGO_ENABLED=0 go build -trimpath -o bin/openbloxd ./cmd/openbloxd
```

- [ ] **Step 2: Verify it builds and starts**

Run: `make build-daemon && ./bin/openbloxd --config deploy/openbloxd.example.yaml`
Expected: refuses with a clear error, because `/run/openbloxd` does not exist and the group is absent. Then:

```bash
sed 's|/run/openbloxd/openbloxd.sock|/tmp/openbloxd.sock|; s|^socket_group:.*|socket_group: ""|' \
  deploy/openbloxd.example.yaml > /tmp/ob.yaml
./bin/openbloxd --config /tmp/ob.yaml
```
Expected: logs `openbloxd listening` with `profiles=2`, and a warning per profile about the unpinned `CHANGEME` digest.

- [ ] **Step 3: Verify the surface answers**

Run: `curl --unix-socket /tmp/openbloxd.sock http://localhost/profiles`
Expected: JSON array with `code-exec` and `browser`.

Run: `curl --unix-socket /tmp/openbloxd.sock -X POST http://localhost/sandboxes -d '{"name":"a","profile":"code-exec","runtime":"runc"}'`
Expected: 400, body kind `invalid`, message naming `runtime`.

- [ ] **Step 4: Commit**

```bash
git add cmd/openbloxd/ deploy/ Makefile
git commit -m "feat(openbloxd): the daemon binary, systemd unit and reference config"
```

---

### Task 10: Broker client — Backend and Sandbox

**Files:**
- Create: `pkg/brokerclient/client.go`
- Create: `pkg/brokerclient/sandbox.go`
- Create: `pkg/brokerclient/options.go`
- Test: `pkg/brokerclient/client_test.go`

**Interfaces:**
- Consumes: `brokerapi` types, `sandbox.Backend`, `sandbox.Sandbox`.
- Produces: `brokerclient.New(socketPath string, opts ...Option) (*Client, error)`; `brokerclient.WithProfile(name string) sandbox.CreateOption`; `brokerclient.WithPreviews(key []byte, baseURL string) Option`.

The client must reject policy-bearing `CreateOption`s rather than drop them. Dropping them silently would repeat the daemon's sin one layer up: the caller would believe a runtime it asked for was applied.

- [ ] **Step 1: Write the failing test**

```go
func TestCreateRejectsPolicyBearingOptions(t *testing.T) {
	c := newTestClient(t, nil)
	cases := []struct {
		name string
		opt  sandbox.CreateOption
		want string
	}{
		{"runtime", sandbox.WithRuntime("runc"), "runtime"},
		{"egress", sandbox.WithEgress(sandbox.EgressUnrestricted), "egress"},
		{"image", sandbox.WithImage("evil.example.com/x"), "image"},
		{"user", sandbox.WithUser("0:0"), "user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Create(context.Background(), "a", WithProfile("code-exec"), tc.opt)
			if !errors.Is(err, sandbox.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %q should name %q", err, tc.want)
			}
		})
	}
}

func TestCreateRequiresProfile(t *testing.T) {
	c := newTestClient(t, nil)
	if _, err := c.Create(context.Background(), "a"); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestCreateAllowsEnvAndLabels(t *testing.T) {
	var got brokerapi.CreateRequest
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		respondJSON(w, http.StatusCreated, brokerapi.Info{Name: "a", State: "running"})
	})
	if _, err := c.Create(context.Background(), "a",
		WithProfile("code-exec"),
		sandbox.WithEnv("K=v"),
		sandbox.WithLabel("tenant", "t1"),
	); err != nil {
		t.Fatal(err)
	}
	if got.Profile != "code-exec" || len(got.Env) != 1 || got.Labels["tenant"] != "t1" {
		t.Errorf("request = %+v", got)
	}
}

func TestErrorKindMapsBackToSentinel(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, http.StatusNotFound, brokerapi.Error{Message: "nope", Kind: brokerapi.KindNotFound})
	})
	_, err := c.Open(context.Background(), "a")
	if !errors.Is(err, sandbox.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
```

`newTestClient` starts an `httptest.Server` on a Unix socket in `t.TempDir()` with the given handler, and points a `Client` at it.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/brokerclient/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Write the implementation**

`pkg/brokerclient/options.go`:

```go
// Package brokerclient reaches openbloxd over its Unix socket.
//
// Its Client satisfies sandbox.Backend, its handle satisfies sandbox.Sandbox,
// and it satisfies preview.Dialer — so a caller swaps one constructor and
// stops needing Docker socket access.
package brokerclient

import (
	"fmt"

	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// profileLabel carries the chosen profile from a CreateOption to Create. It
// travels as a label because CreateOption can only write to a Spec, and is
// stripped before the request is sent.
const profileLabel = "brokerclient.profile"

// WithProfile selects which of the daemon's configured profiles to create
// under. It is the only policy choice a caller has, and the daemon rejects a
// name it does not know.
func WithProfile(name string) sandbox.CreateOption {
	return sandbox.WithLabel(profileLabel, name)
}

// Option configures a Client.
type Option func(*Client) error

// WithPreviews enables Expose, signing credentials with key and serving them
// under baseURL — the same option the Docker backend takes.
//
// Minting a preview touches Docker nowhere: it signs a name, a port and an
// expiry. So it happens here, and the signing key lives in the one process
// that also verifies it. The daemon holds no key.
func WithPreviews(key []byte, baseURL string) Option {
	return func(c *Client) error {
		signer, err := preview.NewSigner(key)
		if err != nil {
			return err
		}
		if baseURL == "" {
			return fmt.Errorf("%w: preview base URL is empty", sandbox.ErrInvalid)
		}
		c.signer = signer
		c.previewBase = baseURL
		return nil
	}
}

// policyFields reports which policy-bearing options a caller set, by comparing
// a resolved Spec against the library defaults.
//
// Dropping these silently would be the same fault the daemon refuses to
// commit, one layer up: the caller would go on believing a runtime it asked
// for had been applied.
func policyFields(spec sandbox.Spec) []string {
	def := sandbox.NewSpec()
	var set []string
	if spec.Image != def.Image {
		set = append(set, "image")
	}
	if spec.Runtime != def.Runtime {
		set = append(set, "runtime")
	}
	if spec.User != def.User {
		set = append(set, "user")
	}
	if spec.Egress != def.Egress {
		set = append(set, "egress")
	}
	if spec.Resources != def.Resources {
		set = append(set, "resources")
	}
	if spec.Lifetime != def.Lifetime {
		set = append(set, "lifetime")
	}
	return set
}
```

`pkg/brokerclient/client.go` holds `Client` with an `*http.Client` whose `Transport.DialContext` ignores the address and dials the Unix socket; `Create`, `Open`, `List`, `Destroy`, `Close`; and a `do` helper that decodes `brokerapi.Error` and returns `fmt.Errorf("%w: %s", brokerapi.ErrorFor(body.Kind), body.Message)`.

`Create` in outline:

```go
func (c *Client) Create(ctx context.Context, name string, opts ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	spec := sandbox.NewSpec(opts...)
	profile := spec.Labels[profileLabel]
	if profile == "" {
		return nil, fmt.Errorf("%w: no profile; pass brokerclient.WithProfile", sandbox.ErrInvalid)
	}
	if set := policyFields(spec); len(set) > 0 {
		return nil, fmt.Errorf(
			"%w: %s %s daemon policy and cannot be set per-request; configure them in the profile",
			sandbox.ErrInvalid, strings.Join(set, ", "), plural(len(set)))
	}
	labels := maps.Clone(spec.Labels)
	delete(labels, profileLabel)
	// … POST /sandboxes with brokerapi.CreateRequest{name, profile, spec.Env, labels}
}
```

`pkg/brokerclient/sandbox.go` holds the handle: `Info`, `Exec`, `ReadFile`, `WriteFile`, `StartProcess`, `Stop`, and `Expose`/`Revoke` implemented locally against `c.signer` exactly as `pkg/docker/expose.go:66-102` does.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/brokerclient/ -v`
Expected: PASS

- [ ] **Step 5: Assert the interfaces are satisfied**

Add to `client.go`:

```go
var (
	_ sandbox.Backend = (*Client)(nil)
	_ preview.Dialer  = (*Client)(nil)
	_ sandbox.Sandbox = (*brokerSandbox)(nil)
)
```

Run: `go build ./...`
Expected: builds. A compile error here means a signature drifted from the library contract.

- [ ] **Step 6: Commit**

```bash
git add pkg/brokerclient/
git commit -m "feat(brokerclient): sandbox.Backend over the openbloxd socket"
```

---

### Task 11: Broker client — DialPort

**Files:**
- Create: `pkg/brokerclient/dial.go`
- Test: `pkg/brokerclient/dial_test.go`

**Interfaces:**
- Consumes: the daemon's `GET /sandboxes/{name}/dial/{port}` upgrade.
- Produces: `(*Client).DialPort(ctx, name string, port int) (net.Conn, error)`.

Use `net/http`'s raw connection rather than the pooled client: the response is a hijacked stream, and returning it to the pool would corrupt the next request on that connection.

- [ ] **Step 1: Write the failing test**

```go
func TestDialPortRoundTrips(t *testing.T) {
	// A daemon stand-in that upgrades and echoes.
	srv := unixServer(t, func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: openblox-stream\r\nConnection: Upgrade\r\n\r\n")
		_, _ = io.Copy(conn, buf)
	})

	c, err := New(srv.socket)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.DialPort(context.Background(), "a", 8080)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Errorf("read %q, want ping", buf)
	}
}

func TestDialPortRejectsOutOfRangePort(t *testing.T) {
	c := newTestClient(t, nil)
	if _, err := c.DialPort(context.Background(), "a", 0); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/brokerclient/ -run TestDialPort -v`
Expected: FAIL — `DialPort` undefined.

- [ ] **Step 3: Write the implementation**

```go
package brokerclient

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// DialPort opens a byte stream to a port inside a sandbox.
//
// The connection is dialled outside the pooled client on purpose: the response
// is a hijacked stream that never completes, and handing it back to the pool
// would corrupt whatever request reused it.
func (c *Client) DialPort(ctx context.Context, name string, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: port %d is out of range", sandbox.ErrInvalid, port)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, fmt.Errorf("dial openbloxd: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://openbloxd/sandboxes/%s/dial/%d", url.PathEscape(name), port), nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", upgradeProto)
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dial port %d in %q: %w", port, name, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dial port %d in %q: %w", port, name, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer func() { _ = conn.Close() }()
		return nil, errorFromResponse(resp)
	}

	// The reader may already hold bytes the daemon sent behind the 101, so the
	// connection must read through it rather than from the socket directly.
	return &upgradedConn{Conn: conn, r: br}, nil
}

// upgradedConn reads through the buffer left over from the handshake.
type upgradedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *upgradedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
```

Add `upgradeProto = "openblox-stream"` as a shared constant. Both sides must agree, so declare it once in `pkg/brokerapi` and reference it from the daemon and the client rather than duplicating the string.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/brokerclient/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/brokerclient/dial.go pkg/brokerclient/dial_test.go pkg/brokerapi/types.go
git commit -m "feat(brokerclient): DialPort over the connection upgrade"
```

---

### Task 12: Adversarial policy tests

**Files:**
- Create: `internal/daemon/policy_test.go`

**Interfaces:**
- Consumes: `Server`, `fakeBackend`.
- Produces: nothing; this task adds only tests.

Asserting a 4xx is the weaker half. The half that matters is asserting that **no value reached the resolved `Spec`** — a handler could return 400 and still have applied something first.

- [ ] **Step 1: Write the test**

```go
func TestNoRequestFieldReachesTheSpec(t *testing.T) {
	bodies := []string{
		`{"name":"a","profile":"code-exec","runtime":"runc"}`,
		`{"name":"a","profile":"code-exec","egress":"unrestricted"}`,
		`{"name":"a","profile":"code-exec","privileged":true}`,
		`{"name":"a","profile":"code-exec","binds":["/:/host"]}`,
		`{"name":"a","profile":"code-exec","pid_mode":"host"}`,
		`{"name":"a","profile":"code-exec","user":"0:0"}`,
		`{"name":"a","profile":"code-exec","cpus":64}`,
		`{"name":"a","profile":"code-exec","memory_mb":1048576}`,
		`{"name":"a","profile":"code-exec","image":"evil.example.com/x"}`,
		`{"name":"a","profile":"code-exec","registry_auth":{"username":"x"}}`,
		`{"name":"a","profile":"code-exec","max_processes":0}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			srv := newTestServer(t)
			fake := srv.backend.(*fakeBackend)

			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body)))

			if rec.Code < 400 || rec.Code > 499 {
				t.Fatalf("status = %d, want 4xx", rec.Code)
			}
			if len(fake.created) != 0 {
				t.Fatalf("a rejected request created a sandbox: %+v", fake.created)
			}
		})
	}
}

func TestAcceptedRequestGetsExactlyTheProfilePolicy(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec","env":["K=v"],"labels":{"t":"1"}}`)))

	got := fake.created["a"]
	want := sandbox.NewSpec(srv.cfg.Profiles["code-exec"].Options()...)
	if got.Runtime != want.Runtime || got.Egress != want.Egress ||
		got.User != want.User || got.Resources != want.Resources || got.Image != want.Image {
		t.Errorf("spec = %+v, want the profile's %+v", got, want)
	}
}

func TestReservedProfileLabelIsRefused(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec","labels":{"openbloxd.profile":"browser"}}`)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — a caller must not forge the profile label", rec.Code)
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/daemon/ -run 'TestNoRequestField|TestAcceptedRequest|TestReservedProfile' -v`
Expected: PASS. If any case fails, the policy is wrong — fix `handleCreate`, not the test.

- [ ] **Step 3: Commit**

```bash
git add internal/daemon/policy_test.go
git commit -m "test(daemon): assert no request field can reach the resolved spec"
```

---

### Task 13: Run the integration suite through the broker

**Files:**
- Create: `pkg/brokerclient/broker_integration_test.go`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the whole stack.
- Produces: CI coverage proving the broker behaves identically to the library.

This is the highest-value test in the plan and costs almost nothing: one interface, one existing suite. It runs on the hosted gVisor runner that already gates merge (#3).

- [ ] **Step 1: Write the harness**

```go
//go:build integration

package brokerclient_test

// startBroker runs an openbloxd against the live Docker daemon on a socket in
// t.TempDir(), and returns a Client pointed at it. The daemon is in-process:
// the point is to exercise the wire and the policy, not the packaging.
func startBroker(t *testing.T) *brokerclient.Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "openbloxd.sock")
	cfg := &daemon.Config{
		Socket:       socket,
		ReapInterval: time.Hour, // no sweeps mid-test
		Profiles: map[string]daemon.Profile{
			"test": {
				Image:        testImage(t),
				Runtime:      "runsc",
				Egress:       "none",
				User:         "1000:1000",
				CPUs:         2,
				MemoryMB:     2048,
				DiskMB:       1024,
				MaxProcesses: 256,
				IdleTimeout:  30 * time.Minute,
				MaxAge:       time.Hour,
			},
		},
	}
	backend, err := docker.New()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := daemon.Listen(socket, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: daemon.New(backend, cfg).Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = backend.Close()
	})

	c, err := brokerclient.New(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
```

`daemon` is an internal package, so this test must live inside the module — it does. If the import is rejected, move the harness to `internal/daemon/broker_integration_test.go` and keep the client assertions there.

- [ ] **Step 2: Port the existing assertions**

For each behaviour in `pkg/docker/sandbox_integration_test.go`, `process_integration_test.go`, `preview_integration_test.go` and `relay_integration_test.go`, add the same assertion driven through `startBroker(t)` instead of `docker.New()`. Cover at minimum: create then exec then read output; write then read a file; start a background process and observe it; expose a port and fetch through the preview handler; destroy is idempotent.

Do not re-verify the isolation caps here — `limits_integration_test.go` already proves those against the library, and the broker applies the identical `Spec`.

- [ ] **Step 3: Add one broker-specific integration assertion**

```go
func TestBrokerRefusesPolicyOptionsAgainstALiveDaemon(t *testing.T) {
	c := startBroker(t)
	_, err := c.Create(context.Background(), "x",
		brokerclient.WithProfile("test"), sandbox.WithRuntime("runc"))
	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if _, err := c.Open(context.Background(), "x"); !errors.Is(err, sandbox.ErrNotFound) {
		t.Error("a refused create must not have created anything")
	}
}
```

- [ ] **Step 4: Run the suite**

Run: `make test-integration` on a gVisor-capable host.
Expected: PASS. On a host without `runsc`, expect `ErrRuntimeUnavailable` — that is the correct failure, not a reason to relax the profile.

- [ ] **Step 5: Wire it into CI**

Add `./pkg/brokerclient/...` to whatever package list the integration job runs, or confirm it already runs module-wide with `-tags integration ./...`. Check the workflow before editing — the repo moved to module-wide integration runs, so this may need no change at all.

- [ ] **Step 6: Commit**

```bash
git add pkg/brokerclient/broker_integration_test.go .github/workflows/ci.yml
git commit -m "test(brokerclient): run the integration suite through the broker"
```

---

### Task 14: Documentation

**Files:**
- Modify: `ARCHITECTURE.md:43-45`, `ARCHITECTURE.md:212-219`
- Modify: `docs/security.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything built above.
- Produces: no code.

- [ ] **Step 1: Amend the transport-wrapper rule**

`ARCHITECTURE.md:43` currently reads:

> The library is the product. `openbloxd` is a transport wrapper over it and must never hold logic the library doesn't. If a behaviour can only be reached over HTTP, it's in the wrong place.

Replace with:

```markdown
The library is the product. `openbloxd` holds no *sandbox* behaviour the library
doesn't — if a way to run code can only be reached over HTTP, it's in the wrong
place. It does hold *policy*, and that is the point: the daemon exists so a
caller can create sandboxes without holding the Docker socket, which is only
true if the isolation policy lives on the daemon's side of the socket. Options
such as `WithRuntime` and `WithEgress` are therefore configuration in
`openbloxd` and are unreachable from a request.
```

- [ ] **Step 2: Update the repository layout block**

`ARCHITECTURE.md:212-219` — add the new packages:

```
pkg/sandbox/       the library — Backend, Sandbox, options, errors
pkg/preview/       preview-link signing + reverse proxy
pkg/brokerapi/     the wire types openbloxd speaks
pkg/brokerclient/  a Backend that reaches openbloxd instead of Docker
cmd/openbloxd/     the policy broker
internal/daemon/   openbloxd's internals — config, routes, policy
deploy/            systemd unit and reference config
```

Note `pkg/proxy/` in the existing block is stale — the package is `pkg/preview/`. Fix it while here.

- [ ] **Step 3: Document the deployment in `docs/security.md`**

Add a section covering: the daemon owns the socket and the caller does not; profiles are the whole policy surface; mount the socket's **directory** rather than the file, because bind-mounting the file leaves a stale inode after a daemon restart; the socket group is the entire access-control list; and `SO_PEERCRED` records the peer uid, which under user-namespace remapping is the remapped one.

- [ ] **Step 4: Verify the docs build**

Run: `mkdocs build --strict` (or confirm the docs workflow passes).
Expected: no warnings. `specs/` and `plans/` sit outside `docs/`, so neither is published.

- [ ] **Step 5: Commit**

```bash
git add ARCHITECTURE.md docs/security.md README.md
git commit -m "docs: openbloxd owns policy, and the deployment that follows"
```

---

## Follow-up, outside this plan

Migrating a caller onto the broker is a change to a different repository and gets its own plan there. In outline: swap the `docker` backend for `brokerclient`; delete every isolation-relevant field (image, runtime, CPU, memory, disk, idle timeout, max age, egress) from the caller's sandbox config; delete its image-resolution helpers; repoint any reaper-first check at `GET /profiles`; and in the caller's container config drop the `docker.sock` mount and docker group membership, mounting the openbloxd socket directory and joining its group instead.

## Self-Review

**Spec coverage.** Every section maps to a task: profiles and the three rules → 2, 5, 12; transport and socket hardening → 3, 9; HTTP surface → 4–7; previews and `DialPort` → 7, 10, 11; registry auth → 8; client and policy-option rejection → 10; errors → 1; testing → 12, 13; the ARCHITECTURE.md amendment → 14; rollout step 1 → tasks 1–14, with steps 2–4 in the follow-up.

**Gaps found and closed while reviewing:**

- `sandbox.Info` has no `Labels` field, so the daemon could not read back the profile it recorded. Task 5 adds it and populates it in `pkg/docker`.
- `upgradeProto` was about to be declared twice, once per side. Task 11 moves it into `pkg/brokerapi` so both reference one constant.
- A caller could forge `openbloxd.profile` through `labels` and defeat the conflict check. Task 5 reserves the key; Task 12 tests it.
- `docker.Option` configures the Backend, so one registry credential covers all profiles. Called out in Task 9 rather than left to be discovered.

**Known deviations from the skill's defaults**, both forced by this repository: the plan lives at `plans/` and the spec at `specs/`, not under `docs/superpowers/`, because `docs/` is the mkdocs source for openblox.sh and anything placed there is published.
