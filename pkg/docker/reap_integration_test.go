//go:build integration

package docker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// The activity timestamp is what the idle bound is measured from, so it has to
// actually land inside the sandbox and be readable back.
func TestExecRecordsActivity(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-activity")
	ctx := context.Background()

	if _, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"true"}}); err != nil {
		t.Fatalf("Exec = %v", err)
	}

	// touch is fire-and-forget, so give it a moment to land.
	ds := sb.(*dockerSandbox)
	var last time.Time
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		if last = ds.lastUsed(ctx); !last.IsZero() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if last.IsZero() {
		t.Fatal("no activity recorded after Exec; the idle bound would measure from creation forever")
	}
	if age := time.Since(last); age > time.Minute {
		t.Errorf("activity timestamp is %s old, want roughly now", age)
	}
}

// If code inside the sandbox can rewrite the activity timestamp, it can refresh
// its own idle deadline and never be reaped.
func TestSandboxCannotForgeItsActivityTimestamp(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-activity-tamper")
	ctx := context.Background()

	res, err := sb.Exec(ctx, sandbox.Command{
		Argv: []string{"sh", "-c", "echo 2099-01-01T00:00:00Z > " + lastUsedPath},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("the sandbox wrote %s; it can postpone its own reaping", lastUsedPath)
	}

	// And the directory itself must not be replaceable either.
	res, err = sb.Exec(ctx, sandbox.Command{
		Argv: []string{"sh", "-c", "touch " + stateDir + "/planted"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("the sandbox created a file in %s", stateDir)
	}
}

func TestReapDestroysASandboxPastItsMaxAge(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	name := "openblox-test-reap-maxage"

	// A max age of a nanosecond is already exceeded by the time Create returns.
	create(t, b, name, sandbox.WithLifetime(sandbox.Lifetime{MaxAge: time.Nanosecond}))

	reaped, err := b.Reap(ctx)
	if err != nil {
		t.Fatalf("Reap = %v", err)
	}
	if !contains(reaped, name) {
		t.Fatalf("Reap returned %v, want it to include %q", reaped, name)
	}
	if _, err := b.Open(ctx, name); err == nil {
		t.Error("sandbox still exists after being reaped")
	}
}

func TestReapDestroysAnIdleSandbox(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	name := "openblox-test-reap-idle"

	create(t, b, name, sandbox.WithLifetime(sandbox.Lifetime{
		IdleTimeout: time.Nanosecond,
		MaxAge:      -1, // disabled, so only the idle path can fire
	}))

	reaped, err := b.Reap(ctx)
	if err != nil {
		t.Fatalf("Reap = %v", err)
	}
	if !contains(reaped, name) {
		t.Fatalf("Reap returned %v, want it to include %q", reaped, name)
	}
}

// The common failure mode for a reaper is reaping too much.
func TestReapLeavesLiveSandboxesAlone(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	name := "openblox-test-reap-survivor"

	create(t, b, name)

	reaped, err := b.Reap(ctx)
	if err != nil {
		t.Fatalf("Reap = %v", err)
	}
	if contains(reaped, name) {
		t.Fatalf("Reap destroyed a sandbox created moments ago: %v", reaped)
	}
	if _, err := b.Open(ctx, name); err != nil {
		t.Errorf("Open after Reap = %v", err)
	}
}

// A container the daemon holds that openblox did not create must be invisible to
// the sweep, whatever its age.
func TestReapIgnoresForeignContainers(t *testing.T) {
	b := newTestBackend(t)

	reaped, err := b.Reap(context.Background())
	if err != nil {
		t.Fatalf("Reap = %v", err)
	}
	for _, name := range reaped {
		if strings.TrimSpace(name) == "" {
			t.Error("Reap destroyed a container with no openblox name label")
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
