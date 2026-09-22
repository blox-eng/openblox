package conformance

import "testing"

// negativeControlExemptions lists Core properties the negative control
// (badBackend) cannot meaningfully falsify, each with the specific confound
// that makes badBackend not unisolated along that dimension — never
// "not applicable" or anything a reader cannot check independently.
//
// This list is deliberately narrow in where it can live: here, in this test
// file, only. Not a Config field, not environment-driven, not reachable by
// any caller — the same reasoning that keeps the property selector and the
// probe targets out of Config. A lever that lets a run measure less than it
// claims, and say so quietly, is exactly the failure mode the rest of this
// package's design removes.
//
// The list must stay exact: TestEveryCorePropertyFailsAgainstNoIsolation
// asserts every exempted property actually PASSES against badBackend, and
// that every entry still names a real Core property. If a probe changes, or
// badBackend changes, such that an exempted property starts failing the way
// an ordinary Core property should, that assertion fails — the list can only
// ever shrink by someone noticing and removing an entry, never grow, or go
// stale, in silence.
//
// The boundary rule for what may go in this map: an exemption may only ever
// name a confound in the HOST ENVIRONMENT — never a property of badBackend
// itself, because that is always a defect in the control and always fixable.
// The distinction is kind, not count. "This host is unprivileged" or "this
// host's busybox lacks renamed-argv0 dispatch" are facts about the machine
// running the suite, outside anyone's control here. "badBackend happens to
// not use a shell" was a fact about code this package owns — the fix for
// that is to fix badBackend (see shellQuoteArgv in bad_backend_test.go), not
// to document around it. Once "the control happens to be correct here" is an
// acceptable reason, the list has no ceiling: for any property, badBackend
// could be made incidentally correct and then documented why, and the
// negative control would stop meaning anything. Under this rule the list is
// 2 of 21, structurally bounded by how much of the host this suite cannot
// itself control — and both entries name the same fact about the machine:
// the suite runs as an unprivileged user.
//
// It was 2, then 1, then 2 again. "writable-mounts-are-noexec-nosuid" was exempted because its
// probe copied /bin/busybox to a renamed path and invoked it, which busybox
// refuses (it resolves its applet from argv[0]), so the attack step never ran
// on any host. That was never really a host confound: it was a probe that
// could not attack anywhere, which proves nothing about any implementation.
// The probe now copies the shell — the one binary a POSIX userland must have
// — and the property fails against badBackend the way an ordinary Core
// property should, so the exemption is gone.
//
// It became 2 again during the final review, and the second entry is worth
// reading as a worked example of the rule rather than an exception to it.
// "no-traversal-out-of-the-guest" was counted as covered while proving
// nothing: it failed only because its own positive control fatalled — the
// host has no /workspace, so `ln -s /etc/shadow /workspace/link` could not
// run and its three traversal reads and its hostile-filename assertion never
// executed. That was a defect in the control, so the control was fixed
// (badSandbox now serves the guest scratch from a per-run host directory and
// creates parents inside it; see guestRoot in bad_backend_test.go). With the
// probe actually running, what is left is a genuine host confound, which is
// what the entry below records.
var negativeControlExemptions = map[string]string{
	"no-traversal-out-of-the-guest": "every target this property's traversal reaches is " +
		"root-only on the host — /etc/shadow (0640 root:shadow) through both symlinks, and " +
		"/etc itself for the write-through-a-symlink leg. badBackend does traverse: it follows " +
		"the symlinks straight out to the host's own files, with no boundary of any kind. The " +
		"kernel then denies the read and the write for lack of privilege, the same denial an " +
		"unprivileged process gets on any host, isolated or not. The confound is privilege, " +
		"not isolation — run the suite as root and this property fails against badBackend the " +
		"way an ordinary Core property should. The remaining leg, the hostile file name, does " +
		"execute and correctly finds no injection: badSandbox.WriteFile is an os call with no " +
		"shell in it, and making it quote badly on purpose would be modelling a different " +
		"carelessness than 'no isolation'.",
	"cannot-write-kernel-knobs": "badBackend runs the probe as the test process's own " +
		"unprivileged uid, with no isolation boundary of its own. The kernel denies the " +
		"/proc and /sys writes and the /proc/kcore read for lack of privilege — the same " +
		"denial an unprivileged process gets on any host, isolated or not. The confound is " +
		"privilege, not isolation, so this property's absence of a marker proves nothing " +
		"about containment when run against badBackend.",
}

// A conformance suite that passes vacuously certifies nothing while looking
// authoritative, which is worse than having none. Every Core property must
// FAIL against a backend with no isolation whatsoever — property by property,
// not merely in aggregate, because an aggregate pass hides the one probe that
// silently stopped working.
//
// The exceptions are the properties in negativeControlExemptions, and only
// those: each is checked here to still PASS against badBackend (the outcome
// its confound predicts) and to still name a real Core property, so the
// exemption list cannot drift out of sync with either core or badBackend's
// actual behavior without this test catching it.
func TestEveryCorePropertyFailsAgainstNoIsolation(t *testing.T) {
	seen := make(map[string]bool, len(negativeControlExemptions))
	covered := 0
	for _, p := range core {
		reason, exempt := negativeControlExemptions[p.name]
		if !exempt {
			covered++
			t.Run(p.name, func(t *testing.T) {
				if !propertyFails(p) {
					t.Errorf("Core property %q PASSED against a backend with no isolation: "+
						"it is asserting nothing, or its probe cannot run", p.name)
				}
			})
			continue
		}
		seen[p.name] = true
		t.Run(p.name+"/exempt", func(t *testing.T) {
			if propertyFails(p) {
				t.Errorf("Core property %q is exempted from the negative control (reason: %s) "+
					"but it FAILED against badBackend — the confound the exemption names no "+
					"longer holds, so the exemption is stale and must be removed", p.name, reason)
			}
		})
	}

	// Every exemption must name a property that still exists in core, or it
	// is measuring nothing and hiding that fact.
	for name := range negativeControlExemptions {
		if !seen[name] {
			t.Errorf("negativeControlExemptions has a stale entry %q that names no Core property", name)
		}
	}

	t.Logf("Core: %d properties; negative control covers %d", len(core), covered)
}

// propertyFails runs one property against badBackend in a throwaway *testing.T
// and reports whether it failed, which is the outcome we require.
//
// testing.RunTests is deprecated but is the only stdlib way to run a
// func(*testing.T) and observe its result without changing property's
// signature away from *testing.T — which the spec fixes via Config.New.
//
// A panicking property is not caught here, and deliberately not: testing runs
// each function in its own goroutine and tRunner re-panics after marking the
// test failed, so a recover on this goroutine could never see it anyway. An
// earlier version wrapped this call in `defer func() { _ = recover() }()`,
// which was inert — the comment claimed a containment that did not exist. A
// property that panics crashes the whole run, loudly, which is the right
// outcome for a probe that is broken rather than merely unsatisfied.
func propertyFails(p property) bool {
	inner := testing.RunTests(func(_, _ string) (bool, error) { return true, nil },
		[]testing.InternalTest{{
			Name: p.name,
			F:    func(t *testing.T) { p.fn(t, Config{Name: "no-isolation", New: newBadBackend}) },
		}})
	return !inner
}
