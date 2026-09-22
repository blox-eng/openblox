// Package conformance measures an implementation of [sandbox.Backend] against
// the properties openblox claims for a sandbox.
//
// It is the adversarial suite openblox runs against its own backend, pointed at
// the interface rather than at one implementation. Run it against your own
// Backend to find out how it scores.
//
//	func TestConformance(t *testing.T) {
//		cfg := conformance.Config{
//			Name: "mine",
//			New:  func() (sandbox.Backend, error) { return mypkg.New() },
//		}
//		conformance.Run(t, cfg)
//		conformance.RunHostLocal(t, cfg)
//	}
//
// [Config.New] takes no *testing.T on purpose: the suite, not the
// implementation, decides what a construction failure means. It closes the
// Backend it built.
//
// # Two tiers
//
// [Run] executes Core: properties expressed entirely through the interface.
// An implementation that cannot satisfy a property fails it, and that is the
// result.
//
// No Core property skips, and none is quietly left out. [Config.New] cannot
// skip — it has no *testing.T to skip with. If a property reaches a skip by
// any other route, or never runs because -run or -skip filtered it out, the
// tier reports the count as a failure: a property that did not run measured
// nothing, and a tier that measured nothing is not a passing one.
//
// There is exactly one legitimate abort, and it is the whole run rather than
// one property: a host that cannot provide the required runtime at all skips
// before any property starts. The reason is reported as a test skip — a
// first-class event, so it reaches `go test -json` consumers and CI reporters
// even on an otherwise-green package-list run, and `go test -v` prints it —
// and is repeated on stderr for a human at a terminal. Note that a plain
// `go test ./...` prints only "ok" for a package that passes, so read the skip,
// not the exit status: a skipped tier is not a passing one.
//
// The other way a run can measure something other than what it claims is the
// reference image, and that one is enforced rather than reported: overriding
// it fails the run. See [Run] and the package's image.go.
//
// [RunHostLocal] executes properties whose evidence lives on the machine
// running the test — the host's process table, the test process's own
// descriptors. They are real coverage, but an implementation that cannot run
// them has not conformed any less, so they are never a Core result: the two
// tiers report under separate subtest names ("core" and "host-local").
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
