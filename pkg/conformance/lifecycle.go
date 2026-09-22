package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// A sandbox must not see another sandbox's filesystem state or environment,
// and destroying one must not leave state a re-created sandbox of the same
// name can see.
func propSandboxesShareNoState(t *testing.T, cfg Config) {
	t.Setenv("OPENBLOX_HOST_SECRET", "host-secret-value")
	b := cfg.New(t)
	a := create(t, cfg, b, "openblox-conf-iso-a", sandbox.WithEnv("TENANT_TOKEN=a-secret"))
	other := create(t, cfg, b, "openblox-conf-iso-b")

	// A's writes have to land before B's inability to see them means anything:
	// if none of them did, B reads nothing for a reason that has nothing to do
	// with isolation, and every check below passes on an absence.
	planted := run(t, a, `echo a-data > /workspace/f; echo a-data > /tmp/f; echo a-data > /dev/shm/f 2>/dev/null
cat /workspace/f /tmp/f 2>/dev/null`)
	if !strings.Contains(planted, "a-data") {
		t.Fatalf("%s: sandbox A could not write the state B is about to be checked for: %q", cfg.Name, planted)
	}

	out := run(t, other, `cat /workspace/f /tmp/f /dev/shm/f 2>/dev/null; env`)
	for _, leaked := range []string{"a-data", "a-secret", "host-secret-value"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%s: sandbox B sees %q", cfg.Name, leaked)
		}
	}
	aEnv := run(t, a, `env`)
	// Same reasoning as the files: B not seeing a-secret proves nothing unless
	// A was actually given it.
	if !strings.Contains(aEnv, "a-secret") {
		t.Fatalf("%s: sandbox A was not given the environment B is being checked for: %q", cfg.Name, aEnv)
	}
	if strings.Contains(aEnv, "host-secret-value") {
		t.Errorf("%s: the calling process's environment leaked into the sandbox", cfg.Name)
	}

	if err := b.Destroy(t.Context(), "openblox-conf-iso-a"); err != nil {
		t.Fatalf("%s: Destroy = %v", cfg.Name, err)
	}
	again := create(t, cfg, b, "openblox-conf-iso-a")
	if out := run(t, again, `cat /workspace/f /tmp/f 2>/dev/null; env`); strings.Contains(out, "a-data") || strings.Contains(out, "a-secret") {
		t.Errorf("%s: a re-created sandbox inherited its predecessor's state: %q", cfg.Name, out)
	}
}

// Under gVisor the guest can SIGKILL its own init, which stops the sandbox. That
// harms nothing but the guest itself; what matters is that it surfaces as a
// prompt error rather than a hang, and that Create brings the sandbox back.
func propCrashedSandboxRecoversThroughCreate(t *testing.T, cfg Config) {
	b := cfg.New(t)
	ctx := t.Context()
	name := "openblox-conf-crash"
	sb := create(t, cfg, b, name)

	// Through an explicit shell, not as bare argv: the reference image ships no
	// kill binary, and propArgvIsNeverAShellBuiltin guarantees argv never
	// reaches the shell's own builtin, so `Argv: []string{"kill", ...}` could
	// not deliver the signal there at all. The guest reaching for a shell to
	// signal init is what this property is about anyway.
	_, _ = sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "kill -9 1"}, Timeout: 10 * time.Second})

	deadline := time.Now().Add(20 * time.Second)
	for {
		current, err := b.Open(ctx, name)
		if err == nil && current.Info().State == sandbox.StateStopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: sandbox still not stopped 20s after its init was killed (err %v)", cfg.Name, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	start := time.Now()
	if _, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"true"}}); !errors.Is(err, sandbox.ErrStopped) {
		t.Errorf("%s: Exec on a crashed sandbox = %v, want ErrStopped", cfg.Name, err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("%s: Exec on a crashed sandbox hung instead of failing", cfg.Name)
	}

	back, err := b.Create(ctx, name, sandbox.WithImage(image()))
	if err != nil {
		t.Fatalf("%s: Create after crash = %v", cfg.Name, err)
	}
	if out := run(t, back, "echo back"); !strings.Contains(out, "back") {
		t.Errorf("%s: sandbox not usable after Create brought it back: %q", cfg.Name, out)
	}
}

// A stopped sandbox is replaced, not revived: its writable storage is gone
// anyway, and reviving it would bring back the policy it was created under
// instead of the one asked for now.
func propStoppedSandboxIsReplacedByCreate(t *testing.T, cfg Config) {
	b := cfg.New(t)
	ctx := t.Context()
	const name = "openblox-conf-restart"
	sb := create(t, cfg, b, name, sandbox.WithLabel("policy", "old"))

	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("%s: Stop = %v", cfg.Name, err)
	}
	back, err := b.Create(ctx, name, sandbox.WithImage(image()), sandbox.WithLabel("policy", "new"))
	if err != nil {
		t.Fatalf("%s: Create = %v", cfg.Name, err)
	}
	if back.Info().State != sandbox.StateRunning {
		t.Errorf("%s: state after Create = %s, want running", cfg.Name, back.Info().State)
	}
	if back.Info().ID == sb.Info().ID {
		t.Errorf("%s: Create restarted the stopped container instead of replacing it", cfg.Name)
	}
	if got := back.Info().Labels["policy"]; got != "new" {
		t.Errorf("%s: policy label = %q, want the options passed to this Create", cfg.Name, got)
	}
	if out := run(t, back, "echo ok"); !strings.Contains(out, "ok") {
		t.Errorf("%s: Exec after replacement: %q", cfg.Name, out)
	}
}

// Argv is executed as a program, never as a shell builtin, even though a shell
// now wraps it to record its process group. "exit 3" as argv names a program
// called exit — which does not exist — not the shell's exit.
func propArgvIsNeverAShellBuiltin(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-builtin")

	res, err := sb.Exec(t.Context(), sandbox.Command{Argv: []string{"exit", "3"}})
	if err == nil && res.ExitCode == 3 {
		t.Errorf("%s: argv[0] \"exit\" ran as the shell builtin", cfg.Name)
	}
}

// propDestroyRemovesTheSandbox is the portable half of the old leak test.
// "ContainerInspect says it is gone" was Docker's way of checking it; the
// property is that the interface stops reporting it, which any implementation
// can be asked.
func propDestroyRemovesTheSandbox(t *testing.T, cfg Config) {
	b := cfg.New(t)
	ctx := t.Context()

	const name = "openblox-conf-destroy"
	if _, err := b.Create(ctx, name, sandbox.WithImage(image())); err != nil {
		t.Fatalf("%s: Create = %v", cfg.Name, err)
	}
	// This property calls b.Create directly, bypassing the create() helper
	// that normally registers this cleanup, because it needs to Destroy
	// itself mid-test and assert on the aftermath. Register the backstop
	// anyway: if the explicit Destroy below fatals, this still runs, so a
	// failure here doesn't leak the sandbox for the rest of the suite.
	t.Cleanup(func() { _ = b.Destroy(context.WithoutCancel(t.Context()), name) })
	if err := b.Destroy(ctx, name); err != nil {
		t.Fatalf("%s: Destroy = %v", cfg.Name, err)
	}

	if _, err := b.Open(ctx, name); !errors.Is(err, sandbox.ErrNotFound) {
		t.Errorf("%s: Open after Destroy = %v, want ErrNotFound", cfg.Name, err)
	}
	infos, err := b.List(ctx)
	if err != nil {
		t.Fatalf("%s: List = %v", cfg.Name, err)
	}
	for _, in := range infos {
		if in.Name == name {
			t.Errorf("%s: List still reports %q after Destroy", cfg.Name, name)
		}
	}

	// Idempotent by contract: destroying an absent sandbox is not an error.
	if err := b.Destroy(ctx, name); err != nil {
		t.Errorf("%s: second Destroy = %v, want nil", cfg.Name, err)
	}
}
