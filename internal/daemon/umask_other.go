//go:build !unix

package daemon

// withSocketUmask does nothing off Unix, where there is no umask to narrow.
//
// openbloxd does not run on these platforms — it wants a Unix socket, POSIX
// file modes and a systemd unit — and Listen would fail on the first of those
// anyway. This file exists so the module still compiles for them, not to
// suggest the daemon works there.
func withSocketUmask(fn func()) { fn() }
