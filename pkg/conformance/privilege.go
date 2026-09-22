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

	out := run(t, sb, `
for d in /tmp /workspace /dev/shm; do
  cp /bin/busybox "$d/bb" 2>/dev/null || continue
  chmod 4755 "$d/bb" 2>/dev/null
  "$d/bb" true 2>/dev/null && echo "EXECUTED $d"
done
su -c id root </dev/null 2>/dev/null | grep -q 'uid=0' && echo ESCALATED
`)
	for _, marker := range []string{"EXECUTED", "ESCALATED"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: %s: %q", cfg.Name, marker, out)
		}
	}
}

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
