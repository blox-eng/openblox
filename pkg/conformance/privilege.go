package conformance

import (
	"errors"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func propNoCapabilities(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-caps")

	out := run(t, sb, `grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status; id -u; id -g`)
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
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-noexec")

	out := run(t, sb, noexecProbe)
	if strings.Contains(out, "NO_SHELL_BINARY") {
		t.Fatalf("%s: probe cannot locate a shell binary to copy, so its attack step cannot run: %q", cfg.Name, out)
	}
	if strings.Contains(out, "NO_SU") {
		t.Fatalf("%s: probe requires su, which the pinned reference image must provide: %q", cfg.Name, out)
	}
	if !strings.Contains(out, "COPIED ") {
		t.Fatalf("%s: the probe could not plant its binary on any writable mount, so nothing below attempted to execute one: %q", cfg.Name, out)
	}
	for _, marker := range []string{"EXECUTED", "ESCALATED"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: %s: %q", cfg.Name, marker, out)
		}
	}
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
// userland keeps it; COPIED and the NO_ markers make every way this can fail
// to attack visible to the assertion instead of silent.
const noexecProbe = `
src=$(command -v sh 2>/dev/null)
[ -n "$src" ] && [ -f "$src" ] || echo NO_SHELL_BINARY
command -v su >/dev/null 2>&1 || echo NO_SU
for d in /tmp /workspace /dev/shm; do
  if cp "$src" "$d/planted" 2>/dev/null; then
    echo "COPIED $d"
  else
    echo "NOCOPY $d"
    continue
  fi
  chmod 4755 "$d/planted" 2>/dev/null
  "$d/planted" -c 'exit 0' 2>/dev/null && echo "EXECUTED $d"
done
su -c id root </dev/null 2>/dev/null | grep -q 'uid=0' && echo ESCALATED
`

func propCreateRefusesRoot(t *testing.T, cfg Config) {
	b := cfg.New(t)
	for _, user := range []string{"0:0", "root", "1000:0"} {
		_, err := b.Create(t.Context(), "openblox-conf-root",
			sandbox.WithImage(image()), sandbox.WithUser(user))
		if !errors.Is(err, sandbox.ErrInvalid) {
			_ = b.Destroy(t.Context(), "openblox-conf-root")
			t.Errorf("%s: Create(user %q) = %v, want ErrInvalid", cfg.Name, user, err)
		}
	}
}
