package docker

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// DialPort opens a byte stream to a port on the sandbox's loopback interface.
//
// The sandbox has no network interface, so there is no address to connect to
// from outside. Instead the connection is carried over the runtime's exec
// channel: a relay runs inside the sandbox, dials 127.0.0.1:port there, and its
// stdin and stdout become the two directions of this connection.
//
// This is the only way to reach a sandbox port without giving the sandbox a
// network, and giving it one would undo the containment openblox exists for. An
// interface — even on a Docker network marked internal — restores a DNS
// resolver to abuse as a covert channel and makes sandboxes reachable from one
// another. Routing through the control channel keeps the default posture intact:
// nothing in, nothing out, except what openblox carries itself.
//
// The cost is one exec per connection, and a dependency on the image providing a
// relay. Both are acceptable for previews, which are few and long-lived.
func (b *Backend) DialPort(ctx context.Context, name string, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: port %d is out of range", sandbox.ErrInvalid, port)
	}
	sb, err := b.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	return sb.(*dockerSandbox).dialPort(ctx, port)
}

// relayScript connects stdin and stdout to a loopback port inside the sandbox.
//
// Two implementations, tried in order, because neither tool is universal: busybox
// images have nc and often no python, while slimmed language images frequently
// have the reverse. Shipping a forwarder in instead is not an option — every
// writable mount is noexec, deliberately.
//
// The port is passed as an argument rather than interpolated, so it is never
// parsed as shell syntax even though it is validated first. The Python fallback
// contains no single quotes, so it survives being a single-quoted shell word.
const relayScript = `
if command -v nc >/dev/null 2>&1; then exec nc 127.0.0.1 "$1"; fi
if command -v python3 >/dev/null 2>&1; then exec python3 -c '
import socket, sys, threading
sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
def upstream():
    try:
        while True:
            chunk = sys.stdin.buffer.read1(65536)
            if not chunk:
                break
            sock.sendall(chunk)
    except Exception:
        pass
    try:
        sock.shutdown(socket.SHUT_WR)
    except Exception:
        pass
threading.Thread(target=upstream, daemon=True).start()
try:
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
except Exception:
    pass
' "$1"; fi
echo "openblox: sandbox image has neither nc nor python3; cannot reach port $1" >&2
exit 127
`

func (s *dockerSandbox) dialPort(ctx context.Context, port int) (net.Conn, error) {
	return s.dialPortWith(ctx, port, relayScript)
}

// dialPortWith is dialPort with the relay script injectable, so the fallback
// paths can be exercised on an image that happens to have both tools.
func (s *dockerSandbox) dialPortWith(ctx context.Context, port int, script string) (net.Conn, error) {
	// The stream outlives this call, so it gets a context of its own; cancelling
	// the dial's context must not tear down an established connection.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	_, attached, err := s.attach(streamCtx, sandbox.Command{
		// A reader is required for the exec to attach stdin, which is the
		// inbound half of the connection.
		Stdin: stdinPlaceholder{},
		Argv:  []string{"sh", "-c", script, "openblox", fmt.Sprint(port)},
	}, "")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("dial port %d in %q: %w", port, s.info.Name, err)
	}

	pr, pw := io.Pipe()
	go func() {
		// The relay's stderr is dropped: a failed connect shows up as an
		// immediate EOF on the stream, which is what a caller can act on.
		_, err := stdcopy.StdCopy(pw, io.Discard, attached.Reader)
		_ = pw.CloseWithError(err)
	}()

	return &execConn{
		reader:   pr,
		attached: attached,
		cancel:   cancel,
		sandbox:  s.info.Name,
		port:     port,
	}, nil
}

// execConn presents a docker exec stream as a net.Conn.
//
// Reads are demultiplexed out of the exec's framed output; writes go straight to
// the hijacked connection, which the runtime feeds to the relay's stdin.
type execConn struct {
	reader   *io.PipeReader
	attached types.HijackedResponse
	cancel   context.CancelFunc
	sandbox  string
	port     int
}

func (c *execConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *execConn) Write(p []byte) (int, error) { return c.attached.Conn.Write(p) }

func (c *execConn) Close() error {
	// Order matters: the hijacked connection must be closed before the pipe, or
	// the demultiplexing goroutine stays blocked on a read that nothing will
	// interrupt — cancelling a context does not unblock a hijacked read.
	c.attached.Close()
	c.cancel()
	return c.reader.Close()
}

// CloseWrite half-closes the connection, signalling end-of-input to the relay
// while leaving the response direction open. net/http uses this on request
// bodies; without it a proxied request with a body would never complete.
func (c *execConn) CloseWrite() error { return c.attached.CloseWrite() }

func (c *execConn) LocalAddr() net.Addr { return execAddr{name: "openblox"} }
func (c *execConn) RemoteAddr() net.Addr {
	return execAddr{name: fmt.Sprintf("%s:%d", c.sandbox, c.port)}
}

// SetDeadline applies to the underlying stream. A read deadline that fires ends
// the connection rather than merely failing one Read: the framed stream cannot
// be resumed once a partial frame has been consumed.
func (c *execConn) SetDeadline(t time.Time) error      { return c.attached.Conn.SetDeadline(t) }
func (c *execConn) SetWriteDeadline(t time.Time) error { return c.attached.Conn.SetWriteDeadline(t) }
func (c *execConn) SetReadDeadline(t time.Time) error  { return c.attached.Conn.SetDeadline(t) }

type execAddr struct{ name string }

func (execAddr) Network() string  { return "openblox-exec" }
func (a execAddr) String() string { return a.name }

// stdinPlaceholder marks the exec as needing stdin attached without supplying
// anything to drain. The inbound half of the connection arrives through Write
// over the life of the connection, so nothing pumps this reader — and nothing
// half-closes stdin either, which draining it would.
type stdinPlaceholder struct{}

func (stdinPlaceholder) Read([]byte) (int, error) { return 0, io.EOF }

var (
	_ net.Conn = (*execConn)(nil)
	// net/http checks for this to half-close request bodies.
	_ interface{ CloseWrite() error } = (*execConn)(nil)
)
