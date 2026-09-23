//go:build integration && kata

// The conformance suite, run against this package's Docker backend with Kata
// Containers as the runtime instead of gVisor. This is evidence, not a gate:
// it runs only in .github/workflows/kata.yml, which nothing requires, and a
// property failing here is a finding to record, not a failure to fix. See
// specs/2026-09-22-kata-evidence.md.
//
// Needs a Docker daemon with Kata's shim registered as the runtime "kata".
package docker

import (
	"context"
	"slices"
	"testing"

	"github.com/blox-eng/openblox/pkg/conformance"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

const kataRuntime = "kata"

// kataBackend is this package's Backend with every sandbox created under Kata.
// Choosing the runtime is the implementation's business, done in Config.New
// like any other construction detail: the suite neither knows nor can be told
// what it is measuring.
//
// The runtime is appended after the caller's options, so it wins over any
// WithRuntime the suite might pass. Clip keeps that append from writing into
// spare capacity in the caller's slice.
type kataBackend struct{ *Backend }

func (k kataBackend) Create(ctx context.Context, name string, opts ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	return k.Backend.Create(ctx, name, append(slices.Clip(opts), sandbox.WithRuntime(kataRuntime))...)
}

func TestConformanceKata(t *testing.T) {
	requireKataApplied(t)
	cfg := conformance.Config{
		Name: "docker+kata",
		New: func() (sandbox.Backend, error) {
			b, err := New()
			if err != nil {
				return nil, err
			}
			return kataBackend{b}, nil
		},
	}
	conformance.Run(t, cfg)
	conformance.RunHostLocal(t, cfg)
}

// requireKataApplied proves, against the live container, that the wrapper
// reaches the daemon before anything is measured. A result labelled Kata but
// measured under another runtime would be worse than no result.
func requireKataApplied(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	b := newTestBackend(t)
	name := "openblox-test-kata-runtime"

	sb, err := kataBackend{b}.Create(ctx, name, sandbox.WithImage(testImage))
	if err != nil {
		t.Fatalf("Create under %q = %v; nothing below would be a Kata result", kataRuntime, err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.Background(), name) })

	inspect, err := b.cli.ContainerInspect(ctx, sb.Info().ID)
	if err != nil {
		t.Fatalf("inspect = %v", err)
	}
	if got := inspect.HostConfig.Runtime; got != kataRuntime {
		t.Fatalf("runtime = %q, want %q: this run would measure the wrong boundary", got, kataRuntime)
	}

	// Destroy the preflight sandbox now rather than leaving it running for
	// the rest of the suite: t.Cleanup above remains as the safety net for
	// the failure paths, but the success path should not leak a VM for the
	// whole run.
	if err := b.Destroy(ctx, name); err != nil {
		t.Fatalf("Destroy preflight sandbox = %v", err)
	}
}
