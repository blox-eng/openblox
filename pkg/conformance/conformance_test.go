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

func TestCoreIsTheClaimedSize(t *testing.T) {
	if len(core) != 21 {
		t.Errorf("core has %d properties, want 21 — update the spec and this test together", len(core))
	}
}

// TestTiersAreDisjoint asserts the real invariant: every property name
// appears exactly once across the two tiers combined. A plain check that the
// two name sets don't intersect would miss a name duplicated within a single
// tier (already covered separately by TestCoreHasNoDuplicateNames, but
// hostLocal has no such test of its own), so this counts occurrences instead.
func TestTiersAreDisjoint(t *testing.T) {
	count := map[string]int{}
	for _, p := range core {
		count[p.name]++
	}
	for _, p := range hostLocal {
		count[p.name]++
	}
	for name, n := range count {
		if n != 1 {
			t.Errorf("%q appears %d times across core and hostLocal combined; a property must be in exactly one tier", name, n)
		}
	}
}
