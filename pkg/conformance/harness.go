package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// probeTimeout bounds every guest probe. Generous: a property must fail
// because the sandbox contained it, never because the box was busy.
const probeTimeout = time.Minute

// run executes a shell script in the sandbox and returns its combined output.
//
// The script is always a caller-side constant. Nothing variable is
// interpolated into it: values go through Argv, because a suite that built its
// probes by string concatenation would be asserting argv-is-never-a-shell
// while violating the premise.
func run(t *testing.T, sb sandbox.Sandbox, script string) string {
	t.Helper()
	res, err := sb.Exec(t.Context(), sandbox.Command{
		Argv:    []string{"sh", "-c", script},
		Timeout: probeTimeout,
	})
	if err != nil {
		t.Fatalf("Exec(%q) = %v", script, err)
	}
	return string(res.Stdout) + string(res.Stderr)
}

// create makes a sandbox on the pinned image and guarantees it is destroyed
// even if the property fails.
func create(t *testing.T, cfg Config, b sandbox.Backend, name string, opts ...sandbox.CreateOption) sandbox.Sandbox {
	t.Helper()
	opts = append([]sandbox.CreateOption{sandbox.WithImage(image())}, opts...)
	sb, err := b.Create(t.Context(), name, opts...)
	if err != nil {
		abortIfRuntimeUnavailable(t, err)
		t.Fatalf("%s: Create(%q) = %v", cfg.Name, name, err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.WithoutCancel(t.Context()), name) })
	return sb
}
