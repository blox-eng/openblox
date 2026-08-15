//go:build unix

package daemon

import "syscall"

// withSocketUmask runs fn with the umask narrowed so that a socket created
// inside it cannot come out more permissive than socketMode.
//
// The umask is process-global and not goroutine-safe, which is safe here only
// because Listen runs once at startup, before anything else creates a file.
// Keep it that way.
func withSocketUmask(fn func()) {
	old := syscall.Umask(0o777 &^ socketMode)
	defer syscall.Umask(old)
	fn()
}
