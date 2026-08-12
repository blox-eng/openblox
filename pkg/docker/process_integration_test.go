//go:build integration

package docker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// StartProcess must return once the process is detached, not once it exits.
func TestStartProcessDetaches(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-startproc")
	ctx := context.Background()

	start := time.Now()
	err := sb.StartProcess(ctx, "sleeper", sandbox.Command{Argv: []string{"sleep", "60"}})
	if err != nil {
		t.Fatalf("StartProcess = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("StartProcess took %s; it waited for the process instead of detaching", elapsed)
	}

	res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "ps -o args | grep -c '[s]leep 60'"}})
	if err != nil {
		t.Fatalf("Exec ps = %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) == "0" {
		t.Error("no sleep process running; StartProcess did not leave it behind")
	}
}

func TestStartProcessIsIdempotent(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-startproc-idem")
	ctx := context.Background()

	cmd := sandbox.Command{Argv: []string{"sleep", "60"}}
	for i := range 3 {
		if err := sb.StartProcess(ctx, "sleeper", cmd); err != nil {
			t.Fatalf("StartProcess #%d = %v", i+1, err)
		}
	}

	res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "ps -o args | grep -c '[s]leep 60'"}})
	if err != nil {
		t.Fatalf("Exec ps = %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "1" {
		t.Errorf("%s sleep processes running, want 1 — StartProcess started duplicates", got)
	}
}

// A process that has exited leaves a stale pid file behind; the next call must
// notice the process is gone and start a fresh one.
func TestStartProcessRestartsAfterExit(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-startproc-restart")
	ctx := context.Background()

	if err := sb.StartProcess(ctx, "shortlived", sandbox.Command{Argv: []string{"true"}}); err != nil {
		t.Fatalf("first StartProcess = %v", err)
	}
	waitFor(t, sb, "! kill -0 \"$(cat /tmp/.openblox/proc/shortlived/pid)\" 2>/dev/null")

	if err := sb.StartProcess(ctx, "shortlived", sandbox.Command{Argv: []string{"sleep", "60"}}); err != nil {
		t.Fatalf("second StartProcess = %v", err)
	}
	res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "ps -o args | grep -c '[s]leep 60'"}})
	if err != nil {
		t.Fatalf("Exec ps = %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) == "0" {
		t.Error("a stale pid file blocked the restart")
	}
}

func TestStartProcessCapturesOutput(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-startproc-log")
	ctx := context.Background()

	err := sb.StartProcess(ctx, "greeter", sandbox.Command{
		Argv: []string{"sh", "-c", "echo hello from the background"},
	})
	if err != nil {
		t.Fatalf("StartProcess = %v", err)
	}
	waitFor(t, sb, "grep -q hello /tmp/.openblox/proc/greeter/log")
}

func TestStartProcessRejectsUnsafeNames(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-startproc-badname")

	err := sb.StartProcess(context.Background(), "../escape", sandbox.Command{Argv: []string{"true"}})
	if err == nil {
		t.Fatal("StartProcess accepted a traversing name")
	}
}

// waitFor polls a shell condition inside the sandbox until it holds.
func waitFor(t *testing.T, sb sandbox.Sandbox, condition string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		res, err := sb.Exec(context.Background(), sandbox.Command{Argv: []string{"sh", "-c", condition}})
		if err != nil {
			t.Fatalf("Exec %q = %v", condition, err)
		}
		if res.ExitCode == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition never held: %s", condition)
}
