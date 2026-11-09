package docker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/pkg/stdcopy"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// runRelay runs relayScript the way the exec does, with PATH limited to dir so
// each test decides which tools the "image" has.
func runRelay(t *testing.T, dir string, port int, stdin io.Reader) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", relayScript, "openblox", strconv.Itoa(port))
	cmd.Env = []string{"PATH=" + dir}
	cmd.Stdin = stdin
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

// toolDir returns a directory holding the named tools: real ones linked from
// the host, or fakes given as script bodies.
func toolDir(t *testing.T, hostTools []string, fakes map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range hostTools {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s is not installed on this host", name)
		}
		if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// An image with neither tool must fail with a message that names the cause,
// not with a connection that silently never opens.
func TestRelayFailsClearlyWithoutNcOrPython(t *testing.T) {
	_, stderr, err := runRelay(t, t.TempDir(), 8080, strings.NewReader(""))

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 {
		t.Fatalf("relay = %v, want exit 127", err)
	}
	if !strings.Contains(stderr, "neither nc nor python3") || !strings.Contains(stderr, "8080") {
		t.Fatalf("stderr = %q, want it to name the missing tools and the port", stderr)
	}
}

func TestRelayPrefersNc(t *testing.T) {
	dir := toolDir(t, []string{"python3"}, map[string]string{"nc": `echo "nc $*"`})

	stdout, _, err := runRelay(t, dir, 8080, strings.NewReader(""))

	if err != nil || stdout != "nc 127.0.0.1 8080\n" {
		t.Fatalf("relay = %q, %v; want nc dialling 127.0.0.1 8080", stdout, err)
	}
}

// The port arrives as an argument, so shell syntax in it is never run.
func TestRelayPassesThePortAsData(t *testing.T) {
	dir := toolDir(t, nil, map[string]string{"nc": `printf '%s\n' "$2"`})
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", relayScript, "openblox", "1; echo injected")
	cmd.Env = []string{"PATH=" + dir}

	out, err := cmd.Output()

	if err != nil || string(out) != "1; echo injected\n" {
		t.Fatalf("relay = %q, %v; want the port handed to nc verbatim", out, err)
	}
}

// echoServer accepts one connection, reads it to end of input, then sends it
// all back. A relay that never half-closes the socket hangs here.
func echoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		got, _ := io.ReadAll(conn)
		_, _ = conn.Write(got)
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// Slimmed language images often ship python3 and no nc. The fallback has to
// carry a payload larger than one read in each direction, and pass the end of
// input on to the service, or a request with a body never completes.
func TestRelayFallsBackToPython(t *testing.T) {
	dir := toolDir(t, []string{"python3"}, nil)
	payload := make([]byte, 300<<10)
	_, _ = rand.Read(payload)

	stdout, stderr, err := runRelay(t, dir, echoServer(t), bytes.NewReader(payload))

	if err != nil {
		t.Fatalf("relay: %v: %s", err, stderr)
	}
	if !bytes.Equal([]byte(stdout), payload) {
		t.Fatalf("relay returned %d bytes, want the %d sent", len(stdout), len(payload))
	}
}

// Nothing listening is an immediate end of stream, which the preview proxy
// reports as a bad gateway. It must not hang.
func TestRelayEndsTheStreamWhenNothingListens(t *testing.T) {
	dir := toolDir(t, []string{"python3"}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	stdout, _, err := runRelay(t, dir, port, strings.NewReader("GET / HTTP/1.0\r\n\r\n"))

	if err == nil || stdout != "" {
		t.Fatalf("relay = %q, %v; want a failed exit and no output", stdout, err)
	}
}

func TestDialPortRejectsPortsOutOfRange(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, err := (&Backend{}).DialPort(context.Background(), "box", port); !errors.Is(err, sandbox.ErrInvalid) {
			t.Errorf("DialPort(%d) = %v, want ErrInvalid", port, err)
		}
	}
}

func TestDialPortOnAStoppedSandboxReportsStopped(t *testing.T) {
	s := newExecDaemon(t, &execDaemon{createStatus: http.StatusConflict})

	if _, err := s.dialPortWith(context.Background(), 8080, "relay"); !errors.Is(err, sandbox.ErrStopped) {
		t.Fatalf("dial = %v, want ErrStopped", err)
	}
}

// echoSession plays a relay that echoes stdin back. It writes noise on stderr
// first, splits every frame across two writes, and on end of input sends
// "bye" and exits.
func echoSession(conn net.Conn, in *bufio.Reader) {
	_, _ = stdcopy.NewStdWriter(conn, stdcopy.Stderr).Write([]byte("relay noise"))
	buf := make([]byte, 4096)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			var frame bytes.Buffer
			_, _ = stdcopy.NewStdWriter(&frame, stdcopy.Stdout).Write(buf[:n])
			half := frame.Len() / 2
			_, _ = conn.Write(frame.Bytes()[:half])
			time.Sleep(5 * time.Millisecond)
			_, _ = conn.Write(frame.Bytes()[half:])
		}
		if err != nil {
			break
		}
	}
	_, _ = stdcopy.NewStdWriter(conn, stdcopy.Stdout).Write([]byte("bye"))
}

func dialEcho(ctx context.Context, t *testing.T) (net.Conn, *execDaemon) {
	t.Helper()
	d := &execDaemon{session: echoSession}
	conn, err := newExecDaemon(t, d).dialPortWith(ctx, 8080, "relay")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, d
}

func TestDialRunsTheRelayWithThePortAndStdinAttached(t *testing.T) {
	_, d := dialEcho(context.Background(), t)

	opts := d.nextCreate(t)

	if !slices.Equal(opts.Cmd, []string{"sh", "-c", "relay", "openblox", "8080"}) {
		t.Fatalf("relay argv = %q", opts.Cmd)
	}
	if !opts.AttachStdin || opts.User != "" {
		t.Fatalf("relay exec: stdin attached %v, user %q; want stdin attached as the sandbox user", opts.AttachStdin, opts.User)
	}
}

// Reads come out of Docker's framed stream: a frame split across writes, read
// through a buffer smaller than the frame, still arrives whole and in order,
// and stderr never reaches the caller.
func TestExecConnCarriesBytesBothWaysAcrossPartialFrames(t *testing.T) {
	conn, _ := dialEcho(context.Background(), t)

	if _, err := conn.Write([]byte("hello, sandbox")); err != nil {
		t.Fatal(err)
	}
	var got []byte
	small := make([]byte, 3)
	for len(got) < len("hello, sandbox") {
		n, err := conn.Read(small)
		if err != nil {
			t.Fatalf("read after %q: %v", got, err)
		}
		got = append(got, small[:n]...)
	}
	if string(got) != "hello, sandbox" {
		t.Fatalf("read %q, want the bytes written", got)
	}
}

// net/http half-closes a request body and then waits for the response. The
// relay must see end of input while the response direction stays open.
func TestCloseWriteEndsInputButKeepsTheResponse(t *testing.T) {
	conn, _ := dialEcho(context.Background(), t)

	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if string(got) != "requestbye" {
		t.Fatalf("read %q, want the echo then the relay's reply to end of input", got)
	}
}

// Close has to free a Read blocked on a relay that sends nothing. Cancelling
// a context does not unblock a hijacked read, so this is Close's job alone.
func TestCloseUnblocksAPendingRead(t *testing.T) {
	conn, _ := dialEcho(context.Background(), t)
	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 64))
		readErr <- err
	}()

	_ = conn.Close()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read returned no error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read still blocked after Close")
	}
}

// The dial's context bounds the dial only. A preview connection outlives the
// request that opened it.
func TestCancellingTheDialContextKeepsTheConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn, _ := dialEcho(ctx, t)
	cancel()

	if _, err := conn.Write([]byte("still here")); err != nil {
		t.Fatalf("write after cancel: %v", err)
	}
	got := make([]byte, len("still here"))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "still here" {
		t.Fatalf("read after cancel = %q, %v", got, err)
	}
}

// A read deadline that fires ends the connection: a partly consumed frame
// cannot be resumed.
func TestReadDeadlineEndsTheConnection(t *testing.T) {
	conn, _ := dialEcho(context.Background(), t)

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 64))
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read = %v, want the deadline", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read ignored its deadline")
	}
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("read after the deadline succeeded; the stream should be over")
	}
}

func TestExecConnNamesTheSandboxPort(t *testing.T) {
	conn, _ := dialEcho(context.Background(), t)

	if got := conn.RemoteAddr(); got.Network() != "openblox-exec" || got.String() != "box:8080" {
		t.Fatalf("RemoteAddr = %s %s, want openblox-exec box:8080", got.Network(), got)
	}
}
