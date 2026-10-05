//go:build integration

package docker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// waitUntilRunning blocks until the command under test has created /tmp/ready,
// so a stop can only land mid-command and never before it started.
func waitUntilRunning(t *testing.T, sb sandbox.Sandbox) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if res, err := sb.Exec(context.Background(), sandbox.Command{Argv: []string{"test", "-f", "/tmp/ready"}}); err == nil && res.ExitCode == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the command under test never started")
}

// A command killed with its sandbox comes back as an ordinary result with a
// non-zero exit, indistinguishable from a command that failed on its own. The
// caller needs to know the sandbox is gone without a second call to find out.
func TestExecKilledWithItsSandboxReportsStopped(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-stopmid")
	ctx := context.Background()

	done := make(chan sandbox.Result, 1)
	go func() {
		res, err := sb.Exec(ctx, sandbox.Command{
			Argv:    []string{"sh", "-c", "echo started; touch /tmp/ready; sleep 30; echo finished"},
			Timeout: 60 * time.Second,
		})
		if err != nil {
			t.Errorf("Exec = %v; a command killed with its sandbox is a result, not an error", err)
		}
		done <- res
	}()
	waitUntilRunning(t, sb)
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	res := <-done

	if !res.Stopped {
		t.Errorf("Stopped = false after the sandbox was stopped mid-command (exit %d)", res.ExitCode)
	}
	if res.OOMKilled {
		t.Error("OOMKilled = true for a sandbox an operator stopped")
	}
	if !strings.Contains(string(res.Stdout), "started") {
		t.Errorf("Stdout = %q, want the output produced before the stop", res.Stdout)
	}
}

// A non-zero exit is the command's own business. Only the sandbox dying makes it
// Stopped, so a command that fails, or kills itself, leaves the sandbox usable
// and the flag unset.
func TestExecThatFailsOnItsOwnLeavesTheSandboxRunning(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-failown")
	ctx := context.Background()

	for name, script := range map[string]string{
		"exit 3":         "exit 3",
		"exit 255":       "exit 255",
		"exit 130":       "exit 130",
		"kills itself":   "kill -9 $$",
		"command absent": "nosuchcommand-xyz",
	} {
		start := time.Now()
		res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", script}})
		if err != nil {
			t.Fatalf("%s: Exec = %v", name, err)
		}
		// Only the exits a death produces may wait for Docker; 255 and 130 are
		// ordinary and must come back at once.
		if (name == "exit 255" || name == "exit 130") && time.Since(start) > stopSettle/2 {
			t.Errorf("%s took %v: an ordinary exit waited for a stop that was never coming", name, time.Since(start))
		}
		if res.ExitCode == 0 {
			t.Fatalf("%s: exit 0, want a failure", name)
		}
		if res.Stopped || res.OOMKilled {
			t.Errorf("%s: Stopped=%v OOMKilled=%v for a command that failed on its own, exit %d",
				name, res.Stopped, res.OOMKilled, res.ExitCode)
		}
	}

	if res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"true"}}); err != nil || res.ExitCode != 0 {
		t.Errorf("the sandbox did not survive its own commands failing: %v, exit %d", err, res.ExitCode)
	}
}
