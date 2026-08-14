package brokerclient

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"

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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/sandboxes/%s/dial/%d", baseURL, pathEscape(name), port), nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", brokerapi.UpgradeProto)
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dial port %d in %q: %w", port, name, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dial port %d in %q: %w", port, name, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, errorFrom(resp)
	}

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
