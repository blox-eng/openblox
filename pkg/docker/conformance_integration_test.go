//go:build integration

// The conformance suite, run against this package's Docker backend. It
// replaces the hand-written adversarial suite that used to live here: the
// properties are the same claims, expressed against sandbox.Backend so any
// implementation can be measured by them, and pkg/docker is simply the first
// implementation to be.
//
// Needs a Docker daemon with the gVisor (runsc) runtime registered, like every
// other integration test here. See CONTRIBUTING.md.
package docker

import (
	"testing"

	"github.com/blox-eng/openblox/pkg/conformance"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

func TestConformance(t *testing.T) {
	cfg := conformance.Config{
		Name: "docker",
		New: func(t *testing.T) sandbox.Backend {
			t.Helper()
			b, err := New()
			if err != nil {
				t.Fatalf("New() = %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
	}
	conformance.Run(t, cfg)
	conformance.RunHostLocal(t, cfg)
}
