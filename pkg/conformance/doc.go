// Package conformance measures an implementation of [sandbox.Backend] against
// the properties openblox claims for a sandbox.
//
// It is the adversarial suite openblox runs against its own backend, pointed at
// the interface rather than at one implementation. Run it against your own
// Backend to find out how it scores.
//
//	func TestConformance(t *testing.T) {
//		cfg := conformance.Config{Name: "mine", New: newBackend}
//		conformance.Run(t, cfg)
//		conformance.RunHostLocal(t, cfg)
//	}
//
// # Two tiers
//
// [Run] executes Core: properties expressed entirely through the interface.
// Nothing in Core skips. An implementation that cannot satisfy a property
// fails it, and that is the result.
//
// [RunHostLocal] executes properties whose evidence lives on the machine
// running the test — the host's process table, the test process's own
// descriptors. They are real coverage, but an implementation that cannot run
// them has not conformed any less, so they are never a Core result.
//
// # Core grows
//
// Properties are added as the threat model grows, so a release can turn a
// passing run red without your code changing. That is intended: a suite frozen
// for compatibility would stop tracking the thing that makes it worth running.
//
// # What it requires
//
// A live backend and the pinned reference image. Probes assume that image's
// userland, which is why it is not configurable: comparability between
// implementations is the point.
package conformance
