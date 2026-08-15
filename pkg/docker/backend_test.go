package docker

import (
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Container names are visible to anything with daemon access, so a caller's
// name — which may carry tenant or user identity — must not survive into one.
func TestContainerNameDoesNotLeakTheCallerName(t *testing.T) {
	secret := "tenant-acme:user-jane:conversation-42"
	got := containerName(secret)

	for _, part := range []string{"tenant-acme", "user-jane", "conversation-42", secret} {
		if strings.Contains(got, part) {
			t.Errorf("containerName(%q) = %q, leaks %q", secret, got, part)
		}
	}
	if !strings.HasPrefix(got, containerPrefix) {
		t.Errorf("containerName = %q, want prefix %q so sweeps cannot match foreign containers", got, containerPrefix)
	}
}

func TestContainerNameIsDeterministicAndDistinct(t *testing.T) {
	same, again := containerName("session-a"), containerName("session-a")
	if same != again {
		t.Error("containerName is not deterministic; session affinity would break")
	}
	if other := containerName("session-b"); same == other {
		t.Errorf("distinct names collide: both map to %q", same)
	}
}

func TestStateFromStatus(t *testing.T) {
	tests := map[string]sandbox.State{
		"running":    sandbox.StateRunning,
		"restarting": sandbox.StateRunning,
		"created":    sandbox.StateStopped,
		"paused":     sandbox.StateStopped,
		"exited":     sandbox.StateStopped,
		"removing":   sandbox.StateStopped,
		"dead":       sandbox.StateError,
		"":           sandbox.StateError,
	}
	for status, want := range tests {
		if got := stateFromStatus(status); got != want {
			t.Errorf("stateFromStatus(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestScratchMountsAreBoundedAndHardened(t *testing.T) {
	const budget = 1 << 30
	mounts := scratchMounts(budget)

	// The scratch paths plus openblox's own state directory.
	if len(mounts) != len(scratchPaths)+1 {
		t.Fatalf("got %d mounts, want %d", len(mounts), len(scratchPaths)+1)
	}
	for path, opts := range mounts {
		if !strings.Contains(opts, "size=") {
			t.Errorf("%s has no size bound: %q — scratch space would be unbounded", path, opts)
		}
		for _, hardening := range []string{"nosuid", "nodev", "noexec"} {
			if !strings.Contains(opts, hardening) {
				t.Errorf("%s missing %s: %q", path, hardening, opts)
			}
		}
	}
}

// The activity timestamp is only a real bound if the guest cannot rewrite it.
// The sandbox runs unprivileged, so the state mount must not be world-writable.
func TestStateMountIsNotWritableByTheSandbox(t *testing.T) {
	opts := scratchMounts(1 << 30)[stateDir]

	if opts == "" {
		t.Fatalf("no tmpfs at %s; the activity timestamp has nowhere to live", stateDir)
	}
	if !strings.Contains(opts, "mode=0755") {
		t.Errorf("%s mounted %q — the guest could forge its own idle deadline", stateDir, opts)
	}
}

func TestBuildConfigAppliesContainment(t *testing.T) {
	spec := sandbox.NewSpec(sandbox.WithImage("alpine:3.20"))
	cfg, hostCfg := buildConfig("session-1", spec)

	if hostCfg.Runtime != sandbox.DefaultRuntime {
		t.Errorf("runtime = %q, want %q", hostCfg.Runtime, sandbox.DefaultRuntime)
	}
	if !hostCfg.ReadonlyRootfs {
		t.Error("rootfs is writable")
	}
	if string(hostCfg.NetworkMode) != "none" {
		t.Errorf("network mode = %q, want none", hostCfg.NetworkMode)
	}
	if hostCfg.PidsLimit == nil {
		t.Error("PidsLimit unset")
	}
	if cfg.Labels[labelName] != "session-1" {
		t.Errorf("name label = %q, want session-1", cfg.Labels[labelName])
	}
	if cfg.Labels[labelManaged] != "true" {
		t.Error("managed label unset; List and the reaper would not see this sandbox")
	}
}

func TestBuildConfigHonoursEgressOptIn(t *testing.T) {
	spec := sandbox.NewSpec(
		sandbox.WithImage("alpine:3.20"),
		sandbox.WithEgress(sandbox.EgressUnrestricted),
	)
	cfg, hostCfg := buildConfig("session-1", spec)

	if string(hostCfg.NetworkMode) == "none" {
		t.Error("network still disabled after opting in to egress")
	}
	if cfg.NetworkDisabled {
		t.Error("NetworkDisabled still set after opting in to egress")
	}
}

// NetworkDisabled reads like belt-and-braces on top of NetworkMode "none", but
// under gVisor it removes the loopback interface too, so nothing inside the
// sandbox can bind a port and previews stop working entirely.
func TestContainmentDoesNotRemoveLoopback(t *testing.T) {
	spec := sandbox.NewSpec(sandbox.WithImage("alpine:3.20"))
	cfg, hostCfg := buildConfig("session-1", spec)

	if cfg.NetworkDisabled {
		t.Error("NetworkDisabled is set; the sandbox has no loopback and cannot serve a preview")
	}
	if string(hostCfg.NetworkMode) != "none" {
		t.Errorf("network mode = %q, want none — that is what provides the containment", hostCfg.NetworkMode)
	}
}

// User labels must not collide with openblox's own bookkeeping.
func TestUserLabelsArePrefixed(t *testing.T) {
	spec := sandbox.NewSpec(
		sandbox.WithImage("alpine:3.20"),
		sandbox.WithLabel("managed", "false"),
	)
	cfg, _ := buildConfig("session-1", spec)

	if cfg.Labels[labelManaged] != "true" {
		t.Error("a user label overwrote the managed label")
	}
	if cfg.Labels[labelUserPfx+"managed"] != "false" {
		t.Error("user label not stored under its prefix")
	}
}

// Info.Labels must expose only what the caller set — never openblox's own
// bookkeeping, which carries no labelUserPfx and so must be excluded by
// construction rather than by an exclusion list.
func TestUserLabelsExcludesBookkeeping(t *testing.T) {
	got := userLabels(map[string]string{
		labelManaged:             "true",
		labelName:                "session-1",
		labelCreatedAt:           "2026-01-01T00:00:00Z",
		labelIdle:                "15m0s",
		labelMaxAge:              "2h0m0s",
		labelDefTmo:              "1m0s",
		labelMaxTmo:              "10m0s",
		labelUserPfx + "profile": "code-exec",
		labelUserPfx + "team":    "infra",
	})

	if len(got) != 2 {
		t.Fatalf("got %d labels, want 2 — bookkeeping leaked: %+v", len(got), got)
	}
	if got["profile"] != "code-exec" || got["team"] != "infra" {
		t.Errorf("stripped labels = %+v, want profile=code-exec team=infra", got)
	}
	for _, bookkeeping := range []string{labelManaged, labelName, labelCreatedAt, labelIdle, labelMaxAge, labelDefTmo, labelMaxTmo} {
		if _, ok := got[bookkeeping]; ok {
			t.Errorf("bookkeeping label %q leaked into user labels", bookkeeping)
		}
	}
}
