package brokerclient

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// DialPort opens a byte stream to a port inside a sandbox.
//
// The connection is dialled outside the pooled client on purpose: the
// response is a hijacked stream that never completes, and handing it back to
// the pool would corrupt whatever request reused it.
func (c *Client) DialPort(ctx context.Context, name string, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: port %d is out of range", sandbox.ErrInvalid, port)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, fmt.Errorf("dial openbloxd: %w", err)
	}

	// ctx stops covering the connection the moment DialContext returns: the
	// handshake below writes and reads on the bare conn, where the request's
	// context is inert. A daemon that accepts and then never answers would
	// block the caller forever, and cancellation would go unnoticed. Bound it
	// explicitly, and release the bound before handing the stream back — the
	// stream is long-lived by design and must not inherit a handshake
	// deadline.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/sandboxes/%s/dial/%d", baseURL, pathEscape(name), port), nil)
	if err != nil {
		stopOnCancel()
		_ = conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", brokerapi.UpgradeProto)
	if err := req.Write(conn); err != nil {
		stopOnCancel()
		_ = conn.Close()
		return nil, fmt.Errorf("dial port %d in %q: %w", port, name, err)
	}

	br := bufio.NewReader(conn)
	//nolint:bodyclose // On a 101 the body isn't a body at all: the connection
	// is taken over as a raw stream and closing it here would tear down the
	// stream we're about to hand back. The non-101 branch below closes both
	// the response body and the connection before returning.
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		stopOnCancel()
		_ = conn.Close()
		return nil, fmt.Errorf("dial port %d in %q: %w", port, name, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		err := errorFrom(resp)
		stopOnCancel()
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, err
	}

	// The handshake is over, so release both of its bounds: the stream is
	// long-lived and must not carry a deadline set for the handshake, nor be
	// closed out from under its owner when ctx is later cancelled.
	stopOnCancel()
	_ = conn.SetDeadline(time.Time{})

	// http.ReadResponse buffers ahead of the 101 line, so bytes the daemon
	// sent immediately behind it may already be sitting in br. Reading from
	// the raw connection instead of br would silently lose them.
	return &upgradedConn{Conn: conn, r: br}, nil
}

// upgradedConn reads through the buffer left over from the handshake, rather
// than the underlying connection directly, so nothing buffered ahead of the
// 101 response is lost.
type upgradedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *upgradedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes the connection, signalling end-of-input while
// leaving the response direction open. net/http asserts for this on request
// bodies; without it, a proxied request with a body (e.g. through
// preview.Handler's httputil.ReverseProxy) never completes.
//
// net.Conn is embedded here as an interface, so its promoted method set is
// fixed at that interface's own — CloseWrite is not among them, even though
// the concrete value underneath (a *net.UnixConn) has one. Without this
// method net/http's type assertion for it just silently fails.
func (c *upgradedConn) CloseWrite() error {
	cw, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("%T does not support CloseWrite", c.Conn)
	}
	return cw.CloseWrite()
}

// net/http type-asserts for this to half-close request bodies.
var _ interface{ CloseWrite() error } = (*upgradedConn)(nil)
