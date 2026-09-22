package conformance

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// probeTimeout bounds every guest probe. Generous: a property must fail
// because the sandbox contained it, never because the box was busy.
const probeTimeout = time.Minute

// plantedSuffix makes every path a probe creates unique to this test process.
//
// Inside a real sandbox the names below are throwaway guest paths. Against the
// negative control they are not: badBackend runs every probe directly on the
// host, as the contributor, so `cp $(command -v sh) /tmp/planted; chmod 4755`
// wrote a setuid shell into a world-writable host directory and left it there
// — a local privilege escalation planted by running the project's own tests,
// had that test process been root. Two separate problems, one fix: a fixed
// name also silently clobbered whatever was already at /tmp/planted,
// /dev/shm/f or /tmp/openblox-conf-knob-control.
//
// A suffix alone is not enough — the artifacts are also removed after the run;
// see sweepPlantedArtifacts, called from TestMain. The chmod itself stays: it
// is what the property measures.
//
// Only [0-9a-f-] by construction, so splicing it into a probe constant cannot
// introduce shell syntax; every splice still goes through shellQuote where the
// whole path is one word.
var plantedSuffix = newPlantedSuffix()

func newPlantedSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("conformance: cannot make planted probe paths unique: " + err.Error())
	}
	return fmt.Sprintf("%d-%x", os.Getpid(), b)
}

// The artifacts probes plant. Basenames where the probe writes the same name
// on several mounts; full paths where it writes one fixed place.
var (
	plantedBinary = "planted-" + plantedSuffix
	plantedFile   = "f-" + plantedSuffix
	knobControl   = "/tmp/openblox-conf-knob-control-" + plantedSuffix
	plantedNode   = "/tmp/sda-" + plantedSuffix
	injectedA     = "/tmp/openblox-conf-pwned-a-" + plantedSuffix
	injectedB     = "/tmp/openblox-conf-pwned-b-" + plantedSuffix
)

// sweepPlantedArtifacts removes, from the host, every file the probes can
// create when they run against a backend that isolates nothing. Called from
// TestMain after the whole run, alongside sweepDetachedMarkers, which does the
// same for leaked processes.
//
// The paths are exact and carry this process's own suffix, so this can never
// remove a file it did not itself create — the same care sweepDetachedMarkers
// takes with its exact-argv match, and for the same reason: strangers run
// `go test ./...` on this repo.
func sweepPlantedArtifacts() {
	for _, dir := range []string{"/tmp", "/dev/shm"} {
		_ = os.Remove(dir + "/" + plantedBinary)
		_ = os.Remove(dir + "/" + plantedFile)
	}
	for _, p := range []string{knobControl, plantedNode, injectedA, injectedB} {
		_ = os.Remove(p)
	}
}

// run executes a shell script in the sandbox and returns its combined output.
//
// The script is always a caller-side constant. Nothing variable is
// interpolated into it: values go through Argv, because a suite that built its
// probes by string concatenation would be asserting argv-is-never-a-shell
// while violating the premise.
func run(t *testing.T, cfg Config, sb sandbox.Sandbox, script string) string {
	t.Helper()
	res, err := sb.Exec(t.Context(), sandbox.Command{
		Argv:    []string{"sh", "-c", script},
		Timeout: probeTimeout,
	})
	if err != nil {
		t.Fatalf("%s: %s: Exec(%q) = %v", cfg.Name, t.Name(), script, err)
	}
	return string(res.Stdout) + string(res.Stderr)
}

// create makes a sandbox on the pinned image and guarantees it is destroyed
// even if the property fails.
//
// Any error here, ErrRuntimeUnavailable included, is a hard failure rather
// than a skip: walk's preflight already proved the runtime could provide a
// sandbox before this property's t.Run started, so its disappearance now is
// a real fault, not the legitimate abort. See preflight's doc comment.
//
// name is reserved: it must never be preflightSandboxName. A property that
// reused it would be racing preflight's own create/destroy of that name,
// which by the time any property runs has already completed — but the
// collision is still a property author's mistake to avoid, not something
// this function guards against.
func create(t *testing.T, cfg Config, b sandbox.Backend, name string, opts ...sandbox.CreateOption) sandbox.Sandbox {
	t.Helper()
	opts = append([]sandbox.CreateOption{sandbox.WithImage(image())}, opts...)
	sb, err := b.Create(t.Context(), name, opts...)
	if err != nil {
		t.Fatalf("%s: Create(%q) = %v", cfg.Name, name, err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.WithoutCancel(t.Context()), name) })
	return sb
}
