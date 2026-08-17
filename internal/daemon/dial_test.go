package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/brokerapi"
)

func TestDialUpgradesAndCopiesBothWays(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).conn = server
	srv.backend.(*fakeBackend).existing = map[string]string{"a": "code-exec"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = http.Serve(ln, srv.Handler()) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	fmt.Fprintf(conn, "GET /sandboxes/a/dial/8080 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: openblox-stream\r\n\r\n")

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status line = %q, want 101", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Prove the downstream -> upstream direction too, not just upstream ->
	// downstream: write from the client side of the TCP connection and read
	// it off the sandbox-side pipe.
	go func() { _, _ = conn.Write([]byte("to-sandbox")) }()
	sbuf := make([]byte, len("to-sandbox"))
	if _, err := io.ReadFull(client, sbuf); err != nil {
		t.Fatal(err)
	}
	if string(sbuf) != "to-sandbox" {
		t.Errorf("upstream read %q", sbuf)
	}

	go func() { _, _ = client.Write([]byte("from-sandbox")) }()
	buf := make([]byte, len("from-sandbox"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "from-sandbox" {
		t.Errorf("read %q", buf)
	}
}

// A sandbox that goes away must release the caller, even when the caller
// sends nothing more. The relay's client-to-sandbox copy sits blocked on a
// read of the caller's connection and only notices the sandbox is gone on its
// next write, so without an explicit close when the other direction ends,
// both goroutines and their descriptors are pinned for the life of the
// process — and nothing bounds the wait, since a hijacked stream is past
// every timeout the server sets.
func TestDialReleasesCallerWhenSandboxCloses(t *testing.T) {
	client, server := net.Pipe()
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).conn = server
	srv.backend.(*fakeBackend).existing = map[string]string{"a": "code-exec"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = http.Serve(ln, srv.Handler()) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	fmt.Fprintf(conn, "GET /sandboxes/a/dial/8080 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: openblox-stream\r\n\r\n")

	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// The sandbox side hangs up while this caller stays silent — the exact
	// shape that used to block forever.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	// A deadline, so a regression fails this test instead of hanging the suite.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("read after sandbox close = %v, want EOF from the daemon closing the stream", err)
	}
}

// newTestServer's config carries two profiles ("code-exec", "browser"), so
// this asserts against what the fixture actually has: both profiles present,
// and sorted by name so the response order is stable across calls.
func TestProfilesReportsLifetimeBounds(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/profiles", nil))

	var out []brokerapi.ProfileInfo
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("profiles = %+v, want 2", out)
	}
	if out[0].Name != "browser" || out[1].Name != "code-exec" {
		t.Fatalf("profiles not sorted by name: %+v", out)
	}
	want := srv.cfg.Profiles["code-exec"]
	if out[1].IdleTimeout != want.IdleTimeout.String() || out[1].MaxAge != want.MaxAge.String() {
		t.Errorf("code-exec lifetime bounds = %+v, want idle=%s max=%s", out[1], want.IdleTimeout, want.MaxAge)
	}
}
