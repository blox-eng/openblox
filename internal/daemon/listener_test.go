package daemon

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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
	// Create a stale socket by listening and immediately closing.
	// This leaves behind the socket file.
	ln0, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln0.Close()
	// Now path is a socket file left behind from an unclean shutdown.

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
	// Group resolution fails before socket creation, so no socket exists.
	// This test verifies the pre-listen refusal path, not cleanup.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("Listen refused, but socket path should not exist after pre-listen error")
	}
}

func TestListenRefusesZeroByteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	// Create a zero-byte regular file at the socket path
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(path, "")
	if err == nil {
		_ = ln.Close()
		t.Fatal("expected Listen to refuse a zero-byte file")
	}

	// Verify the file still exists and wasn't deleted
	if _, statErr := os.Stat(path); statErr != nil {
		t.Error("Listen must not delete non-socket files, even zero-byte ones")
	}
}

func TestListenCleansUpOnChownFailure(t *testing.T) {
	// This test requires a non-root user to reliably fail chown to an
	// inaccessible group. Skip if running as root.
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}

	// Find a group the current user is not a member of.
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("could not get current user: %v", err)
	}

	userGroups, err := currentUser.GroupIds()
	if err != nil {
		t.Skipf("could not get user groups: %v", err)
	}

	userGroupMap := make(map[string]bool)
	for _, g := range userGroups {
		userGroupMap[g] = true
	}

	// Find a group not in the user's list. Start with system groups (low GIDs)
	// which are far less likely to be in a typical user's membership.
	var inaccessibleGroup string
	for gidInt := 1; gidInt < 10000; gidInt++ {
		gidStr := strconv.Itoa(gidInt)
		if !userGroupMap[gidStr] {
			g, err := user.LookupGroupId(gidStr)
			if err == nil && g != nil {
				inaccessibleGroup = g.Name
				break
			}
		}
	}

	if inaccessibleGroup == "" {
		t.Skip("could not find a group to test chown failure with")
	}

	path := filepath.Join(t.TempDir(), "openbloxd.sock")
	ln, err := Listen(path, inaccessibleGroup)
	if err == nil {
		_ = ln.Close()
		t.Fatal("expected Listen to fail when chown fails to inaccessible group")
	}

	// Verify the socket was cleaned up (removed) after the chown failure.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("Listen must clean up socket when post-listen operations fail")
	}
}
