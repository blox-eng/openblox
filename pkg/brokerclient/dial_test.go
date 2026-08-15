package brokerclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// TestDialPortRoundTrips proves bytes actually flow both ways over the
// upgraded connection, not merely that a 101 arrived: it writes from the
// client, echoes on the daemon stand-in, and reads the echo back.
func TestDialPortRoundTrips(t *testing.T) {
	c := newTestClientMux(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: openblox-stream\r\nConnection: Upgrade\r\n\r\n")
		_, _ = io.Copy(conn, buf)
	}))

	conn, err := c.DialPort(context.Background(), "a", 8080)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Errorf("read %q, want ping", buf)
	}
}

// TestDialPortRoundTripsBytesPipelinedBehindThe101 proves the client reads
// through the bufio.Reader used for the handshake rather than the raw
// connection: bytes the daemon writes immediately behind its 101 response —
// before the client has issued a single Read — must not be lost.
func TestDialPortRoundTripsBytesPipelinedBehindThe101(t *testing.T) {
	c := newTestClientMux(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		// Write the 101 and the payload in one shot so both land in the
		// client's read buffer together, ahead of any client-side Read.
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: openblox-stream\r\nConnection: Upgrade\r\n\r\npong!")
		_, _ = io.Copy(conn, buf)
	}))

	conn, err := c.DialPort(context.Background(), "a", 8080)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong!" {
		t.Errorf("read %q, want pong! (bytes sent behind the 101 were lost)", got)
	}
}

// TestDialPortCloseWriteSignalsEndOfInput proves CloseWrite actually
// half-closes the connection: the peer's read must observe EOF while the
// connection is still usable to read the peer's response afterward. A stub
// CloseWrite that does nothing would leave the peer's read blocked forever
// instead, which this test would catch via its timeout.
func TestDialPortCloseWriteSignalsEndOfInput(t *testing.T) {
	sawEOF := make(chan struct{}, 1)
	c := newTestClientMux(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: openblox-stream\r\nConnection: Upgrade\r\n\r\n")

		// A read that only returns once the client half-closes its write side.
		if _, err := io.ReadAll(buf); err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		sawEOF <- struct{}{}
		_, _ = io.WriteString(conn, "bye")
	}))

	conn, err := c.DialPort(context.Background(), "a", 8080)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("connection returned by DialPort does not implement CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	select {
	case <-sawEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("server never observed end-of-input; CloseWrite did not half-close the connection")
	}

	got := make([]byte, 3)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "bye" {
		t.Errorf("read %q after CloseWrite, want bye", got)
	}
}

func TestDialPortRejectsOutOfRangePort(t *testing.T) {
	c := newTestClient(t, nil)
	if _, err := c.DialPort(context.Background(), "a", 0); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if _, err := c.DialPort(context.Background(), "a", 65536); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

// TestDialPortMapsDaemonError proves a non-101 response is decoded as the
// daemon's own error body and mapped through the same kind-to-sentinel path
// as every other client method, so errors.Is against sandbox sentinels works
// here too.
func TestDialPortMapsDaemonError(t *testing.T) {
	c := newTestClientMux(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "no such sandbox", "kind": "not_found"})
	}))

	_, err := c.DialPort(context.Background(), "missing", 8080)
	if !errors.Is(err, sandbox.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
