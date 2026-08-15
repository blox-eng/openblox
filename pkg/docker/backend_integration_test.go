//go:build integration

// These tests need a Docker daemon with the gVisor (runsc) runtime registered.
// See CONTRIBUTING.md. Run with: make test-integration
//
// pkg/brokerclient/broker_integration_test.go re-runs some of these (open,
// destroy) through openbloxd. That suite is hand-mirrored, not shared code —
// keep the two in step deliberately, since nothing else will notice drift.
package docker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

const testImage = "alpine:3.20"

func newTestBackend(t *testing.T) *Backend {
	t.Helper()
	b, err := New()
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// create makes a sandbox and guarantees it is destroyed even if the test fails.
func create(t *testing.T, b *Backend, name string, opts ...sandbox.CreateOption) sandbox.Sandbox {
	t.Helper()
	ctx := context.Background()
	opts = append([]sandbox.CreateOption{sandbox.WithImage(testImage)}, opts...)
	sb, err := b.Create(ctx, name, opts...)
	if err != nil {
		t.Fatalf("Create(%q) = %v", name, err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.Background(), name) })
	return sb
}

func TestCreateIsIdempotent(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	name := "openblox-test-idempotent"

	first := create(t, b, name)
	second, err := b.Create(ctx, name, sandbox.WithImage(testImage))
	if err != nil {
		t.Fatalf("second Create = %v", err)
	}

	if first.Info().ID != second.Info().ID {
		t.Errorf("Create returned a different container on repeat: %s vs %s",
			first.Info().ID, second.Info().ID)
	}
}

func TestOpenAndDestroy(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	name := "openblox-test-lifecycle"

	create(t, b, name)

	if _, err := b.Open(ctx, name); err != nil {
		t.Fatalf("Open after Create = %v", err)
	}
	if err := b.Destroy(ctx, name); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	if _, err := b.Open(ctx, name); !errors.Is(err, sandbox.ErrNotFound) {
		t.Errorf("Open after Destroy = %v, want ErrNotFound", err)
	}
	// Idempotent: destroying an absent sandbox is not an error.
	if err := b.Destroy(ctx, name); err != nil {
		t.Errorf("second Destroy = %v, want nil", err)
	}
}

func TestOpenAbsentReportsNotFound(t *testing.T) {
	b := newTestBackend(t)
	_, err := b.Open(context.Background(), "openblox-test-does-not-exist")
	if !errors.Is(err, sandbox.ErrNotFound) {
		t.Errorf("Open(absent) = %v, want ErrNotFound", err)
	}
}

// The security posture is a property of what actually reaches the runtime, not
// of what the Spec says. This asserts against the live container.
func TestContainmentIsAppliedToTheRuntime(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	name := "openblox-test-containment"

	sb := create(t, b, name)

	inspect, err := b.cli.ContainerInspect(ctx, sb.Info().ID)
	if err != nil {
		t.Fatalf("inspect = %v", err)
	}
	hc := inspect.HostConfig

	if hc.Runtime != sandbox.DefaultRuntime {
		t.Errorf("runtime = %q, want %q — isolation boundary is not gVisor", hc.Runtime, sandbox.DefaultRuntime)
	}
	if !hc.ReadonlyRootfs {
		t.Error("root filesystem is writable")
	}
	if string(hc.NetworkMode) != "none" {
		t.Errorf("network mode = %q, want \"none\"", hc.NetworkMode)
	}
	if len(hc.CapDrop) == 0 || hc.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", hc.CapDrop)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != int64(sandbox.DefaultMaxProcesses) {
		t.Errorf("PidsLimit = %v, want %d — a fork bomb would exhaust host PIDs", hc.PidsLimit, sandbox.DefaultMaxProcesses)
	}
	if hc.Memory != int64(sandbox.DefaultMemoryBytes) {
		t.Errorf("Memory = %d, want %d", hc.Memory, int64(sandbox.DefaultMemoryBytes))
	}
	if hc.NanoCPUs != int64(sandbox.DefaultCPUs*1e9) {
		t.Errorf("NanoCPUs = %d, want %d", hc.NanoCPUs, int64(sandbox.DefaultCPUs*1e9))
	}
	if !hasSecurityOpt(hc.SecurityOpt, "no-new-privileges") {
		t.Errorf("SecurityOpt = %v, missing no-new-privileges", hc.SecurityOpt)
	}
	for _, p := range scratchPaths {
		if _, ok := hc.Tmpfs[p]; !ok {
			t.Errorf("no writable tmpfs at %s; a read-only rootfs leaves nowhere to write", p)
		}
	}
	if inspect.Config.User == "" || inspect.Config.User == "root" || strings.HasPrefix(inspect.Config.User, "0:") {
		t.Errorf("user = %q, want non-root", inspect.Config.User)
	}
}

// Proves the guest really is running under gVisor rather than the host kernel.
func TestSandboxRunsUnderGvisorKernel(t *testing.T) {
	b := newTestBackend(t)

	sb := create(t, b, "openblox-test-kernel")

	out := execInContainer(t, b, sb.Info().ID, []string{"uname", "-r"})
	if !strings.Contains(out, "gvisor") {
		t.Errorf("guest kernel = %q, want a gVisor kernel — syscalls are reaching the host", strings.TrimSpace(out))
	}
}

// The DNS half matters as much as the TCP half: an IP-layer firewall still
// leaves a resolver reachable, which is a usable exfiltration channel.
func TestSandboxHasNoEgressAndNoResolver(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-egress")

	out := execInContainer(t, b, sb.Info().ID, []string{
		"sh", "-c",
		`(wget -T2 -q -O- http://1.1.1.1 >/dev/null 2>&1 && echo TCP_REACHABLE) || echo TCP_BLOCKED; ` +
			`(nslookup example.com >/dev/null 2>&1 && echo DNS_RESOLVES) || echo DNS_BLOCKED`,
	})

	if !strings.Contains(out, "TCP_BLOCKED") {
		t.Errorf("outbound TCP reachable from sandbox: %q", out)
	}
	if !strings.Contains(out, "DNS_BLOCKED") {
		t.Errorf("DNS resolves from sandbox — covert channel is open: %q", out)
	}
}

func TestCreateRejectsUnavailableRuntime(t *testing.T) {
	b := newTestBackend(t)
	_, err := b.Create(context.Background(), "openblox-test-badruntime",
		sandbox.WithImage(testImage),
		sandbox.WithRuntime("definitely-not-a-registered-runtime"))

	if !errors.Is(err, sandbox.ErrRuntimeUnavailable) {
		t.Fatalf("Create with missing runtime = %v, want ErrRuntimeUnavailable (must never fall back)", err)
	}
}

func TestCreateRejectsDiskLargerThanMemory(t *testing.T) {
	b := newTestBackend(t)
	_, err := b.Create(context.Background(), "openblox-test-badresources",
		sandbox.WithImage(testImage),
		sandbox.WithResources(sandbox.Resources{MemoryBytes: 1 << 28, DiskBytes: 1 << 30}))

	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("Create with disk > memory = %v, want ErrInvalid", err)
	}
}

func TestListReportsManagedSandboxes(t *testing.T) {
	b := newTestBackend(t)
	name := "openblox-test-list"
	create(t, b, name)

	items, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List = %v", err)
	}
	for _, it := range items {
		if it.Name == name {
			return
		}
	}
	t.Errorf("List did not include %q; got %d sandboxes", name, len(items))
}

func hasSecurityOpt(opts []string, want string) bool {
	for _, o := range opts {
		if strings.Contains(o, want) {
			return true
		}
	}
	return false
}

// execInContainer runs a command directly through the Docker API. The backend's
// own Exec is not implemented yet, and these tests must not wait on it.
func execInContainer(t *testing.T, b *Backend, id string, argv []string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	created, err := b.cli.ContainerExecCreate(ctx, id, container.ExecOptions{
		Cmd:          argv,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		t.Fatalf("exec create = %v", err)
	}
	attached, err := b.cli.ContainerExecAttach(ctx, created.ID, container.ExecAttachOptions{})
	if err != nil {
		t.Fatalf("exec attach = %v", err)
	}
	defer attached.Close()

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := attached.Reader.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}
