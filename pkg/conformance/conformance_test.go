package conformance

import (
	"strings"
	"testing"
)

func TestImageIsPinnedByDigest(t *testing.T) {
	t.Setenv("OPENBLOX_CONFORMANCE_IMAGE", "")
	got := image()
	if !strings.Contains(got, "@sha256:") {
		t.Errorf("image() = %q, want a digest pin: a tag can be repointed by whoever controls the registry", got)
	}
	if !strings.HasPrefix(got, "ghcr.io/blox-eng/openblox-sandbox") {
		t.Errorf("image() = %q, want the reference image", got)
	}
}

func TestImageOverrideIsHonoured(t *testing.T) {
	t.Setenv("OPENBLOX_CONFORMANCE_IMAGE", "example.test/img:1")
	if got := image(); got != "example.test/img:1" {
		t.Errorf("image() = %q, want the override", got)
	}
}

func TestCoreHasNoDuplicateNames(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range core {
		if seen[p.name] {
			t.Errorf("duplicate Core property name %q", p.name)
		}
		seen[p.name] = true
	}
}
