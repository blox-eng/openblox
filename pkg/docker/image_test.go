package docker

import "testing"

// A tag can be repointed by whoever controls the registry; a digest cannot. The
// image is the guest's entire userland, so the distinction is the difference
// between running what you reviewed and running whatever is there today.
func TestIsDigestPinned(t *testing.T) {
	pinned := []string{
		"alpine@sha256:abc123",
		"ghcr.io/blox-eng/openblox-sandbox@sha256:deadbeef",
		"registry.example.test:5000/team/img@sha256:0011",
	}
	for _, ref := range pinned {
		if !IsDigestPinned(ref) {
			t.Errorf("IsDigestPinned(%q) = false, want true", ref)
		}
	}

	loose := []string{
		"alpine",
		"alpine:3.20",
		"ghcr.io/blox-eng/openblox-sandbox:0.2.0",
		"registry.example.test:5000/team/img",
		// A port in the host is not a digest, and neither is an empty one.
		"example.test:5000/img@",
		"example.test:5000/img@md5:abc",
	}
	for _, ref := range loose {
		if IsDigestPinned(ref) {
			t.Errorf("IsDigestPinned(%q) = true, want false", ref)
		}
	}
}
