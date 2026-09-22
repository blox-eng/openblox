package conformance

import "os"

// referenceImage is the userland every probe executes in.
//
// Pinned by digest, not by tag: SECURITY.md says a tag can be repointed by
// whoever controls the registry, and a suite that pulled a mutable tag would
// let that party replace the probes' userland and turn every property green.
// The rule this project asks of its users applies to the suite that measures
// them.
const referenceImage = "ghcr.io/blox-eng/openblox-sandbox:0.8.1@sha256:073cab42b00101e7c7a6c95f514bb943f29e1addd7dfb33c9a74d62de6bf8277"

// imageOverrideEnv exists for developing the suite itself. A run that uses it
// announces the fact on stderr — not through t.Logf, which go test discards on
// a passing non-verbose run — so an overridden run cannot be presented as a
// conformant one. See walk and announce.
const imageOverrideEnv = "OPENBLOX_CONFORMANCE_IMAGE"

func image() string {
	if v := os.Getenv(imageOverrideEnv); v != "" {
		return v
	}
	return referenceImage
}
