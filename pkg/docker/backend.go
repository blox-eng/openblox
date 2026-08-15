// Package docker implements the openblox sandbox contract on Docker with the
// gVisor (runsc) runtime.
//
// It holds no state of its own. Container labels are the sandbox registry, so
// sandboxes survive the process that created them and several processes may
// manage the same set without coordinating.
package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Label keys openblox writes on every container it owns.
const (
	labelManaged   = "sh.openblox.managed"
	labelName      = "sh.openblox.name"
	labelCreatedAt = "sh.openblox.created-at"
	labelIdle      = "sh.openblox.idle-timeout"
	labelMaxAge    = "sh.openblox.max-age"
	labelDefTmo    = "sh.openblox.default-timeout"
	labelMaxTmo    = "sh.openblox.max-timeout"
	labelUserPfx   = "sh.openblox.user."
)

// containerPrefix namespaces our containers so a sweep can never match a
// container openblox did not create.
const containerPrefix = "openblox-"

// scratchPaths are the writable mounts every sandbox gets. The root filesystem
// is read-only, so without these nothing could write anywhere.
var scratchPaths = []string{"/tmp", "/workspace"}

// openblox's own bookkeeping inside a sandbox.
//
// stateDir is a separate tmpfs from the scratch paths, and deliberately owned by
// root with mode 0755 while the sandbox itself runs unprivileged. The guest can
// read it but cannot write it, so code running in the sandbox cannot forge its
// own activity timestamp to keep itself alive. It is tiny and fixed-size, so it
// is not drawn from the caller's disk budget.
const (
	stateDir      = "/run/openblox"
	lastUsedPath  = stateDir + "/last-used"
	stateDirBytes = 64 << 10
)

// Backend creates sandboxes as Docker containers.
type Backend struct {
	cli *client.Client

	// previews is nil unless WithPreviews was passed, in which case Expose
	// reports that rather than minting a URL nothing serves.
	previews *previews

	// registryAuth is the base64url X-Registry-Auth value used when pulling.
	// Empty means anonymous, which is what openblox did before this existed.
	registryAuth string
}

// Option configures a Backend at construction.
type Option func(*Backend) error

// New connects to the Docker daemon using the standard environment
// (DOCKER_HOST, DOCKER_CERT_PATH, DOCKER_API_VERSION).
func New(opts ...Option) (*Backend, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("connect to docker: %w", err)
	}
	b := &Backend{cli: cli}
	for _, opt := range opts {
		if err := opt(b); err != nil {
			_ = cli.Close()
			return nil, err
		}
	}
	return b, nil
}

// Close releases the Docker client. Running sandboxes are left alone.
func (b *Backend) Close() error { return b.cli.Close() }

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
		// Docker's own encoder, rather than a hand-rolled marshal-and-base64:
		// the X-Registry-Auth header's exact encoding is the daemon's to
		// define, and borrowing it means a change there cannot silently
		// desync from us (see TestRegistryAuthEncodesAsDockerExpects).
		blob, err := registry.EncodeAuthConfig(registry.AuthConfig{Username: username, Password: password})
		if err != nil {
			return fmt.Errorf("encode registry auth: %w", err)
		}
		b.registryAuth = blob
		return nil
	}
}

// Create returns a running sandbox for name, creating it if absent.
func (b *Backend) Create(ctx context.Context, name string, opts ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: sandbox name is empty", sandbox.ErrInvalid)
	}
	spec := sandbox.NewSpec(opts...)
	if err := spec.Resources.Validate(); err != nil {
		return nil, err
	}
	if spec.Image == "" {
		return nil, fmt.Errorf("%w: no image; pass WithImage", sandbox.ErrInvalid)
	}

	if sb, err := b.Open(ctx, name); err == nil {
		return sb, nil
	} else if !errors.Is(err, sandbox.ErrNotFound) {
		return nil, err
	}

	if err := b.assertRuntime(ctx, spec.Runtime); err != nil {
		return nil, err
	}
	if err := b.ensureImage(ctx, spec.Image); err != nil {
		return nil, err
	}

	cfg, hostCfg := buildConfig(name, spec)
	created, err := b.cli.ContainerCreate(ctx, cfg, hostCfg, nil, nil, containerName(name))
	if err != nil {
		// Lost a race with a concurrent Create; the winner's sandbox is fine.
		if cerrdefs.IsConflict(err) {
			return b.Open(ctx, name)
		}
		return nil, fmt.Errorf("create sandbox %q: %w", name, err)
	}

	if err := b.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		// Roll back rather than leave a created-but-dead container behind for
		// the reaper to puzzle over.
		_ = b.cli.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("start sandbox %q: %w", name, err)
	}

	return b.Open(ctx, name)
}

// Open returns an existing sandbox, or ErrNotFound.
func (b *Backend) Open(ctx context.Context, name string) (sandbox.Sandbox, error) {
	inspect, err := b.cli.ContainerInspect(ctx, containerName(name))
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %q", sandbox.ErrNotFound, name)
		}
		return nil, fmt.Errorf("inspect sandbox %q: %w", name, err)
	}
	if inspect.Config == nil || inspect.Config.Labels[labelManaged] != "true" {
		return nil, fmt.Errorf("%w: %q exists but is not managed by openblox", sandbox.ErrInvalid, name)
	}
	labels := inspect.Config.Labels
	return &dockerSandbox{
		cli:            b.cli,
		id:             inspect.ID,
		info:           infoFrom(inspect.ID, labels, inspect.Config.Image, inspect.State),
		defaultTimeout: parseDurationLabel(labels[labelDefTmo], sandbox.DefaultCommandTimeout),
		maxTimeout:     parseDurationLabel(labels[labelMaxTmo], sandbox.MaxCommandTimeout),
		previews:       b.previews,
	}, nil
}

// List returns every sandbox this backend manages.
func (b *Backend) List(ctx context.Context) ([]sandbox.Info, error) {
	containers, err := b.cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("label", labelManaged+"=true")),
	})
	if err != nil {
		return nil, fmt.Errorf("list sandboxes: %w", err)
	}
	out := make([]sandbox.Info, 0, len(containers))
	for _, c := range containers {
		out = append(out, sandbox.Info{
			Name:      c.Labels[labelName],
			ID:        c.ID,
			Image:     c.Image,
			State:     stateFromStatus(c.State),
			CreatedAt: parseTimeLabel(c.Labels[labelCreatedAt]),
			Labels:    userLabels(c.Labels),
		})
	}
	return out, nil
}

// Destroy removes a sandbox. Destroying an absent sandbox is not an error.
func (b *Backend) Destroy(ctx context.Context, name string) error {
	err := b.cli.ContainerRemove(ctx, containerName(name), container.RemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	})
	if err != nil && !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("destroy sandbox %q: %w", name, err)
	}
	return nil
}

// assertRuntime fails when the host cannot provide the requested isolation.
//
// This never falls back to the default runtime. A sandbox silently running on
// runc when the caller asked for gVisor is worse than a failed create, because
// the caller goes on trusting a boundary that is not there.
func (b *Backend) assertRuntime(ctx context.Context, runtime string) error {
	info, err := b.cli.Info(ctx)
	if err != nil {
		return fmt.Errorf("inspect docker daemon: %w", err)
	}
	if _, ok := info.Runtimes[runtime]; !ok {
		return fmt.Errorf("%w: runtime %q is not registered with the docker daemon", sandbox.ErrRuntimeUnavailable, runtime)
	}
	return nil
}

// buildConfig translates a Spec into Docker's create payload. Every containment
// control is set here, unconditionally.
func buildConfig(name string, spec sandbox.Spec) (*container.Config, *container.HostConfig) {
	labels := map[string]string{
		labelManaged:   "true",
		labelName:      name,
		labelCreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		labelIdle:      spec.Lifetime.IdleTimeout.String(),
		labelMaxAge:    spec.Lifetime.MaxAge.String(),
		labelDefTmo:    spec.DefaultTimeout.String(),
		labelMaxTmo:    spec.MaxTimeout.String(),
	}
	for k, v := range spec.Labels {
		labels[labelUserPfx+k] = v
	}

	cfg := &container.Config{
		Image:  spec.Image,
		Labels: labels,
		User:   spec.User,
		Env:    spec.Env,
		// The sandbox must stay up between Exec calls; the image's own entrypoint
		// is irrelevant to us and may exit immediately.
		Entrypoint: []string{"/bin/sh", "-c", "while :; do sleep 3600; done"},
		Cmd:        nil,
		WorkingDir: "/workspace",
		// NetworkDisabled is deliberately NOT set, and setting it would look like
		// extra safety while costing real function. Under gVisor it removes the
		// network stack outright, including the loopback interface: a server
		// inside the sandbox cannot bind 127.0.0.1, and nothing can reach it.
		// Previews depend on exactly that.
		//
		// NetworkMode "none" below is what provides the containment. It leaves
		// loopback — which reaches nothing but the sandbox itself — and gives the
		// sandbox no external interface, no route off the host, and no resolver.
	}

	hostCfg := &container.HostConfig{
		Runtime:        spec.Runtime,
		ReadonlyRootfs: true,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		Tmpfs:          scratchMounts(spec.Resources.DiskBytes),
		Resources: container.Resources{
			NanoCPUs:  int64(spec.Resources.CPUs * 1e9),
			Memory:    spec.Resources.MemoryBytes,
			PidsLimit: pidsLimit(spec.Resources.MaxProcesses),
		},
		// Never restart. A sandbox that resurrects itself outlives the reaper.
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
	}
	if spec.Egress == sandbox.EgressNone {
		hostCfg.NetworkMode = "none"
	}
	return cfg, hostCfg
}

// scratchMounts sizes the writable tmpfs paths. The budget is split evenly so
// filling one cannot starve the other.
func scratchMounts(diskBytes int64) map[string]string {
	per := diskBytes / int64(len(scratchPaths))
	out := make(map[string]string, len(scratchPaths)+1)
	for _, p := range scratchPaths {
		mode := "1777"
		if p != "/tmp" {
			mode = "0777"
		}
		out[p] = fmt.Sprintf("rw,nosuid,nodev,noexec,size=%d,mode=%s", per, mode)
	}
	// Mode 0755: root-writable, world-readable. See stateDir.
	out[stateDir] = fmt.Sprintf("rw,nosuid,nodev,noexec,size=%d,mode=0755", stateDirBytes)
	return out
}

func pidsLimit(n int) *int64 {
	if n <= 0 {
		return nil
	}
	v := int64(n)
	return &v
}

// containerName derives a Docker-safe name from a caller-supplied one.
//
// The caller's name is hashed rather than sanitised: it may carry tenant or user
// identity, and container names are visible to anything with daemon access.
func containerName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return containerPrefix + hex.EncodeToString(sum[:])[:32]
}

func stateFromStatus(status string) sandbox.State {
	switch status {
	case "running", "restarting":
		return sandbox.StateRunning
	case "created", "paused", "exited", "removing":
		return sandbox.StateStopped
	default:
		return sandbox.StateError
	}
}

func parseDurationLabel(v string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// userLabels extracts the caller's own labels from a container's full label
// set, stripping labelUserPfx. openblox's own bookkeeping labels (managed,
// name, created-at, the timeout labels) carry no such prefix and are excluded
// by construction, not by an exclusion list — so a new bookkeeping label added
// later cannot leak in here by accident.
func userLabels(labels map[string]string) map[string]string {
	var out map[string]string
	for k, v := range labels {
		if name, ok := strings.CutPrefix(k, labelUserPfx); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[name] = v
		}
	}
	return out
}

func parseTimeLabel(v string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}
	}
	return t
}
