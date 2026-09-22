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
var negativeControlExemptions = map[string]string{
	"cannot-write-kernel-knobs": "badBackend runs the probe as the test process's own " +
		"unprivileged uid, with no isolation boundary of its own. The kernel denies the " +
		"/proc and /sys writes and the /proc/kcore read for lack of privilege — the same " +
		"denial an unprivileged process gets on any host, isolated or not. The confound is " +
		"privilege, not isolation, so this property's absence of a marker proves nothing " +
		"about containment when run against badBackend.",
	"writable-mounts-are-noexec-nosuid": "badBackend runs the probe as the test " +
		"process's own unprivileged uid, and the probe's attack step depends on copying " +
		"/bin/busybox to a renamed path and invoking it as a multi-call binary. On a stock " +
		"CI runner (and on some developer hosts) that binary is either absent or does not " +
		"support renamed-argv0 dispatch, so the attack step never runs at all — the probe " +
		"exits with no marker regardless of whether the mount is noexec. The confound is " +
		"missing/incompatible host tooling, not isolation.",
	"argv-is-never-a-shell-builtin": "badBackend's Exec calls Go's exec.Command(cmd.Argv[0], " +
		"cmd.Argv[1:]...) directly (see badSandbox.Exec in bad_backend_test.go) — it never " +
		"wraps argv in a shell, the same absence of a shell the property is checking for. " +
		"argv[0] \"exit\" is looked up via exec.LookPath as a program named exit, which does " +
		"not exist on a stock host, so Start fails and the property's err==nil&&ExitCode==3 " +
		"check never has a chance to observe a shell builtin running. The confound is that " +
		"badBackend, despite isolating nothing, happens to share the property's own " +
		"never-use-a-shell mechanism for Exec — not a gap in isolation.",
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
func propertyFails(p property) bool {
	var failed bool
	func() {
		defer func() { _ = recover() }()
		inner := testing.RunTests(func(_, _ string) (bool, error) { return true, nil },
			[]testing.InternalTest{{
				Name: p.name,
				F:    func(t *testing.T) { p.fn(t, Config{Name: "no-isolation", New: newBadBackend}) },
			}})
		failed = !inner
	}()
	return failed
}
