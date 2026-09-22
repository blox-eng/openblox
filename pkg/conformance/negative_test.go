package conformance

import "testing"

// A conformance suite that passes vacuously certifies nothing while looking
// authoritative, which is worse than having none. Every Core property must
// FAIL against a backend with no isolation whatsoever — property by property,
// not merely in aggregate, because an aggregate pass hides the one probe that
// silently stopped working.
func TestEveryCorePropertyFailsAgainstNoIsolation(t *testing.T) {
	for _, p := range core {
		t.Run(p.name, func(t *testing.T) {
			if !propertyFails(p) {
				t.Errorf("Core property %q PASSED against a backend with no isolation: "+
					"it is asserting nothing, or its probe cannot run", p.name)
			}
		})
	}
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
