package conformance

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func propNoCapabilities(t *testing.T, cfg Config) {
	b := newBackend(t, cfg)
	sb := create(t, cfg, b, "openblox-conf-caps")

	out := run(t, cfg, sb, `grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status; id -u; id -g`)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 7 {
		t.Fatalf("%s: unexpected probe output: %q", cfg.Name, out)
	}
	for _, l := range lines[:5] {
		if _, v, _ := strings.Cut(l, ":"); strings.Trim(strings.TrimSpace(v), "0") != "" {
			t.Errorf("%s: capability set not empty: %q", cfg.Name, l)
		}
	}
	if lines[5] == "0" || lines[6] == "0" {
		t.Errorf("%s: running as uid %s gid %s, want non-root", cfg.Name, lines[5], lines[6])
	}
}

// Every writable mount is noexec and nosuid, so the guest can neither run a
// binary it wrote nor plant a setuid one.
func propWritableMountsAreNoexecNosuid(t *testing.T, cfg Config) {
	b := newBackend(t, cfg)
	sb := create(t, cfg, b, "openblox-conf-noexec")

	out := run(t, cfg, sb, noexecProbe)
	if strings.Contains(out, "NO_SHELL_BINARY") {
		t.Fatalf("%s: probe cannot locate a shell binary to copy, so its attack step cannot run: %q", cfg.Name, out)
	}
	if !strings.Contains(out, "COPIED ") {
		t.Fatalf("%s: the probe could not plant its binary on any writable mount, so nothing below attempted to execute one: %q", cfg.Name, out)
	}
	if strings.Contains(out, "EXECUTED") {
		t.Errorf("%s: EXECUTED: %q", cfg.Name, out)
	}

	// The nosuid half cannot be demonstrated by attack: noexec already stops
	// the planted setuid copy from running, so the chmod above is never
	// observed either way, and there is no second attack that could observe it
	// from a non-root uid — which propCreateRefusesRoot guarantees is the only
	// uid this suite ever runs as. Asserting the flags the guest itself can
	// read closes that: it is a positive assertion, so unlike a marker it
	// cannot pass on an absence and needs no control of its own.
	//
	// An earlier form tried `su -c id root` for an ESCALATED marker. That
	// marker cannot fire from a non-root uid whatever the mount flags are,
	// because su demands a password — a leg that was green because it could
	// not run, which is the very class this suite exists to find.
	mountinfo := run(t, cfg, sb, `cat /proc/self/mountinfo`)
	if strings.TrimSpace(mountinfo) == "" {
		t.Fatalf("%s: the guest's own mount table is empty, so the flags below cannot be checked", cfg.Name)
	}
	for _, line := range strings.Split(out, "\n") {
		dir, ok := strings.CutPrefix(strings.TrimSpace(line), "COPIED ")
		if !ok {
			continue
		}
		opts, found := mountOptionsFor(mountinfo, dir)
		if !found {
			t.Errorf("%s: no mount in the guest's table governs the writable path %s: %q", cfg.Name, dir, mountinfo)
			continue
		}
		for _, flag := range []string{"noexec", "nosuid"} {
			if !slices.Contains(strings.Split(opts, ","), flag) {
				t.Errorf("%s: writable mount %s is not %s: %q", cfg.Name, dir, flag, opts)
			}
		}
	}
}

// mountOptionsFor returns the per-mount options governing dir, read from a
// /proc/self/mountinfo dump: the entry whose mount point is the longest prefix
// of dir. A writable directory need not be a mount point itself, so the
// enclosing mount is what its flags come from.
//
// mountinfo fields are, in order: id, parent, major:minor, root, mount point,
// per-mount options. The variable-length optional fields that follow are
// terminated by "-", which is why nothing past index 5 is read here.
func mountOptionsFor(mountinfo, dir string) (string, bool) {
	best, bestOpts := "", ""
	found := false
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		mp, opts := f[4], f[5]
		if mp != dir && !strings.HasPrefix(dir, strings.TrimSuffix(mp, "/")+"/") {
			continue
		}
		if !found || len(mp) > len(best) {
			best, bestOpts, found = mp, opts, true
		}
	}
	return bestOpts, found
}

// noexecProbe plants a copy of the shell on each writable mount, makes it
// setuid, and runs it.
//
// It copies the shell rather than /bin/busybox, which the original form used.
// busybox resolves its applet from argv[0], so a copy named anything else is
// not a valid applet and refuses to run — the attack step failed
// deterministically, on every host and every image, whatever the mount flags
// were, and the property passed on an absent marker. A probe whose attack
// cannot run proves nothing about any implementation. The shell is the one
// binary a POSIX userland must have, and command -v finds it wherever that
// userland keeps it; COPIED, NOCOPY and NO_SHELL_BINARY make every way this
// can fail to attack visible to the assertion instead of silent.
//
// The planted copy carries this run's unique suffix and is removed afterwards
// — see plantedSuffix, which explains why a fixed name here was a host-side
// privilege-escalation hazard rather than a tidiness problem. The chmod stays:
// it is the nosuid half of what this property measures.
var noexecProbe = `
src=$(command -v sh 2>/dev/null)
[ -n "$src" ] && [ -f "$src" ] || echo NO_SHELL_BINARY
for d in /tmp /workspace /dev/shm; do
  if cp "$src" "$d/` + plantedBinary + `" 2>/dev/null; then
    echo "COPIED $d"
  else
    echo "NOCOPY $d"
    continue
  fi
  chmod 4755 "$d/` + plantedBinary + `" 2>/dev/null
  "$d/` + plantedBinary + `" -c 'exit 0' 2>/dev/null && echo "EXECUTED $d"
done
`

func propCreateRefusesRoot(t *testing.T, cfg Config) {
	b := newBackend(t, cfg)
	for _, user := range []string{"0:0", "root", "1000:0"} {
		_, err := b.Create(t.Context(), "openblox-conf-root",
			sandbox.WithImage(image()), sandbox.WithUser(user))
		if !errors.Is(err, sandbox.ErrInvalid) {
			_ = b.Destroy(t.Context(), "openblox-conf-root")
			t.Errorf("%s: Create(user %q) = %v, want ErrInvalid", cfg.Name, user, err)
		}
	}
}
