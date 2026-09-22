package conformance

import (
	"strings"
	"testing"
)

// controlPlaneSockets are the sockets that own the machine. Reaching any of
// them from inside a sandbox is a host takeover, not a containment weakness.
//
// Suite-owned and not configurable: a Config field for probe targets would let
// an implementation narrow the list to the ones it happens to pass, and would
// turn a testing library into a request-forgery gadget that runs inside
// somebody else's isolation boundary and reports what it reached.
var controlPlaneSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
	"/run/podman/podman.sock",
	"/run/openbloxd/openbloxd.sock",
}

func propNoControlPlaneSocket(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-sockets")

	// Both assertions below read an absent marker as containment, so establish
	// first that the two mechanisms which produce those markers work at all in
	// this sandbox: an existence test that must say PRESENT, and a read that
	// must say READ. Without this a missing `[` or a missing cat would make
	// every check below pass having attempted nothing.
	if out := run(t, sb, `[ -e /etc ] && echo PRESENT; cat /etc/hostname >/dev/null 2>&1 && echo READ`); !strings.Contains(out, "PRESENT") || !strings.Contains(out, "READ") {
		t.Fatalf("%s: the probe's own existence test and read do not work, so the absences below would prove nothing: %q", cfg.Name, out)
	}

	for _, p := range controlPlaneSockets {
		// The path is a package constant, so this interpolation cannot carry
		// anything a caller supplied.
		if out := run(t, sb, `[ -e `+shellQuote(p)+` ] && echo PRESENT`); strings.Contains(out, "PRESENT") {
			t.Errorf("%s: %s is visible inside the sandbox", cfg.Name, p)
		}
	}

	// World-readable on the host, root-only in the image: either way the
	// sandbox user must not read it. A file that is not there cannot be read
	// either, which is not the same claim, so require it to exist first.
	if out := run(t, sb, `[ -e /etc/shadow ] && echo PRESENT`); !strings.Contains(out, "PRESENT") {
		t.Fatalf("%s: /etc/shadow is absent, so failing to read it says nothing about permissions: %q", cfg.Name, out)
	}
	if out := run(t, sb, `cat /etc/shadow >/dev/null 2>&1 && echo READ`); strings.Contains(out, "READ") {
		t.Errorf("%s: sandbox user read /etc/shadow", cfg.Name)
	}
}

// shellQuote single-quotes a package constant for use in a probe. It exists so
// the quoting is visible and reviewable rather than implied by %q, and it
// rejects anything it cannot quote safely rather than emitting it.
func shellQuote(s string) string {
	if strings.ContainsAny(s, "'\n") {
		panic("conformance: probe constant is not safely quotable: " + s)
	}
	return "'" + s + "'"
}

// /proc and /sys are gVisor's own synthetic views. A write through either
// would be reconfiguring the kernel the sandbox runs on.
func propCannotWriteKernelKnobs(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-procsys")

	// CONTROL_WROTE and CONTROL_READ are the same two mechanisms the four
	// attempts below use, aimed at a path that must work. Without them a shell
	// that could not redirect, or a missing cat, would leave all four markers
	// absent and the property would pass having attempted nothing.
	out := run(t, sb, `
echo 1 > /tmp/openblox-conf-knob-control 2>/dev/null && echo CONTROL_WROTE
cat /proc/self/status >/dev/null 2>&1 && echo CONTROL_READ
echo 1 > /proc/sys/vm/drop_caches 2>/dev/null && echo WROTE_PROC_SYS
echo 1 > /proc/sysrq-trigger 2>/dev/null && echo WROTE_SYSRQ
echo x > /sys/kernel/uevent_helper 2>/dev/null && echo WROTE_SYS
cat /proc/kcore >/dev/null 2>&1 && echo READ_KCORE
`)
	if !strings.Contains(out, "CONTROL_WROTE") || !strings.Contains(out, "CONTROL_READ") {
		t.Fatalf("%s: the probe cannot write or read at all, so the absences below would prove nothing: %q", cfg.Name, out)
	}
	for _, marker := range []string{"WROTE_PROC_SYS", "WROTE_SYSRQ", "WROTE_SYS", "READ_KCORE"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: %s: %q", cfg.Name, marker, out)
		}
	}
}

func propNoBlockDevices(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-dev")

	// Each of the three attempts below is read as contained when its marker is
	// absent, so prove first that each one can run: that /dev is populated and
	// the device test works (a char device must be found), and that mknod and
	// mount are actually present. A missing binary would otherwise be
	// indistinguishable from a denied syscall.
	out := run(t, sb, `
for d in /dev/* /dev/*/*; do [ -c "$d" ] && echo CONTROL_CHAR && break; done
command -v mknod >/dev/null 2>&1 || echo NO_MKNOD
command -v mount >/dev/null 2>&1 || echo NO_MOUNT
for d in /dev/* /dev/*/*; do [ -b "$d" ] && echo "BLOCK $d"; done
mknod /tmp/sda b 8 0 2>/dev/null && echo MADE_NODE
mount -t tmpfs none /tmp 2>/dev/null && echo MOUNTED
`)
	if !strings.Contains(out, "CONTROL_CHAR") {
		t.Fatalf("%s: the probe found no character device under /dev, so it is not reading a populated /dev and its absence of block devices proves nothing: %q", cfg.Name, out)
	}
	for _, missing := range []string{"NO_MKNOD", "NO_MOUNT"} {
		if strings.Contains(out, missing) {
			t.Fatalf("%s: %s: the pinned reference image must provide it, or the attempt below never runs: %q", cfg.Name, missing, out)
		}
	}
	for _, marker := range []string{"BLOCK", "MADE_NODE", "MOUNTED"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: %s: %q", cfg.Name, marker, out)
		}
	}
}

// File operations run as the sandbox user inside the sandbox, so a symlink or
// a ".." can only resolve within the guest's own filesystem — never the
// host's, and never past what that user may read.
func propNoTraversalOutOfGuest(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-traverse")
	ctx := t.Context()

	// The reads below are read as contained when they return nothing, so the
	// symlinks they traverse have to exist first: an ln that silently failed
	// would leave three paths that simply are not there, and the property
	// would pass having traversed nothing.
	out := run(t, sb, `ln -s /etc/shadow /workspace/link; ln -s / /workspace/root
[ -L /workspace/link ] && [ -L /workspace/root ] && echo LINKED`)
	if !strings.Contains(out, "LINKED") {
		t.Fatalf("%s: the probe could not plant its symlinks, so nothing below traverses one: %q", cfg.Name, out)
	}

	for _, p := range []string{"/workspace/link", "/workspace/root/etc/shadow", "/workspace/../etc/shadow"} {
		rc, err := sb.ReadFile(ctx, p)
		if err != nil {
			continue
		}
		body := make([]byte, 64)
		n, _ := rc.Read(body)
		_ = rc.Close()
		if n > 0 {
			t.Errorf("%s: ReadFile(%q) returned %d bytes of a root-only file", cfg.Name, p, n)
		}
	}

	// Writing through a symlink into the read-only root must fail, not land.
	err := sb.WriteFile(ctx, "/workspace/root/etc/openblox-planted", 0o644, strings.NewReader("x"))
	if err == nil {
		t.Errorf("%s: WriteFile through a symlink wrote into the read-only root filesystem", cfg.Name)
	}
	// A hostile file name is data, not syntax.
	name := "/workspace/$(touch /tmp/pwned);`touch /tmp/pwned2`\n-rf"
	if err := sb.WriteFile(ctx, name, 0o644, strings.NewReader("x")); err != nil {
		t.Fatalf("%s: WriteFile(hostile name) = %v", cfg.Name, err)
	}
	if out := run(t, sb, `[ -e /tmp/pwned ] || [ -e /tmp/pwned2 ] && echo INJECTED`); strings.Contains(out, "INJECTED") {
		t.Errorf("%s: a file name was executed as shell", cfg.Name)
	}
}
