package daemon

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
)

// socketMode is owner+group read/write and nothing for others. Access to this
// socket is access to sandbox creation, so the group is the whole ACL.
const socketMode = 0o660

// Listen creates the Unix socket the daemon serves on.
//
// It refuses to start rather than serve on a socket it could not lock down: a
// permissive socket is indistinguishable from a working one until something
// uses it, and by then the caller is trusting a boundary that is not there.
//
// A leftover socket from an unclean shutdown is removed first. Only a socket —
// removing anything else would let a misconfigured path delete a real file.
func Listen(socketPath, group string) (net.Listener, error) {
	if info, err := os.Stat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace %q: not a socket", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale socket %q: %w", socketPath, err)
		}
	}

	gid := -1
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return nil, fmt.Errorf("resolve socket group %q: %w", group, err)
		}
		if gid, err = strconv.Atoi(g.Gid); err != nil {
			return nil, fmt.Errorf("parse gid for group %q: %w", group, err)
		}
	}

	// net.Listen derives the new socket's mode from the umask, so under the
	// usual 022 it lands as 0755 and is reachable by everyone until the Chmod
	// below runs. That window is not theoretical: the kernel queues
	// connections on a listening socket before Accept is ever called, so a
	// local process can connect inside it and have its request served once the
	// chmod lands. Narrowing the umask across the call means the socket is
	// never permissive in the first place.
	var ln net.Listener
	var err error
	withSocketUmask(func() { ln, err = net.Listen("unix", socketPath) })
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", socketPath, err)
	}

	// Chmod anyway: the umask can only clear bits, so this is what makes the
	// final mode the stated one rather than whatever the umask happened to
	// leave. It also keeps the guarantee if the umask dance above ever moves.
	if err := os.Chmod(socketPath, socketMode); err != nil {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("set mode on %q: %w", socketPath, err)
	}
	if gid >= 0 {
		if err := os.Chown(socketPath, -1, gid); err != nil {
			_ = ln.Close()
			_ = os.Remove(socketPath)
			return nil, fmt.Errorf("set group on %q: %w", socketPath, err)
		}
	}
	return ln, nil
}
