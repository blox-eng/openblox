package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListenCreatesSocketWithRestrictedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	ln, err := Listen(path, "")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket mode = %o, want 660", perm)
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(path, "")
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	_ = ln.Close()
}

func TestListenFailsOnUnknownGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	ln, err := Listen(path, "definitely-not-a-real-group")
	if err == nil {
		_ = ln.Close()
		t.Fatal("expected Listen to refuse an unresolvable group")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a refused Listen must not leave a socket behind")
	}
}
