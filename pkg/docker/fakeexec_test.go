package docker

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// execDaemon answers the three calls an exec makes: create, start and inspect.
// Start hijacks the connection as Docker does, and hands the raw stream to
// session, which plays the command: it reads the command's stdin from in and
// writes its framed output to conn.
type execDaemon struct {
	// created receives the options of every exec create, in order.
	created chan container.ExecOptions
	// createStatus, when set, refuses every exec create with that status.
	createStatus int
	session      func(conn net.Conn, in *bufio.Reader)
	exitCode     int
}

func newExecDaemon(t *testing.T, d *execDaemon) *dockerSandbox {
	t.Helper()
	d.created = make(chan container.ExecOptions, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/c1/exec"):
			var opts container.ExecOptions
			if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
				t.Errorf("exec create body: %v", err)
			}
			d.created <- opts
			if d.createStatus != 0 {
				w.WriteHeader(d.createStatus)
				_, _ = w.Write([]byte(`{"message":"refused"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"exec1"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec/exec1/start"):
			// The body must be consumed before the hijack: closing a socket with
			// unread input sends a reset, which loses the output already written.
			_, _ = io.Copy(io.Discard, r.Body)
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer endStream(conn, buf.Reader)
			_, _ = conn.Write([]byte("HTTP/1.1 101 UPGRADED\r\n" +
				"Content-Type: application/vnd.docker.multiplexed-stream\r\n" +
				"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n"))
			if d.session != nil {
				d.session(conn, buf.Reader)
			}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/exec/exec1/json"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ExitCode": d.exitCode, "Running": false})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	cli, err := client.NewClientWithOpts(client.WithHost("tcp://"+srv.Listener.Addr().String()), client.WithVersion("1.45"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return &dockerSandbox{cli: cli, id: "c1", info: sandbox.Info{Name: "box"}, defaultTimeout: time.Minute}
}

// endStream ends the command's output the way the daemon does when a command
// exits: a half-close, then whatever stdin is left is drained, so the close
// that follows is clean rather than a reset.
func endStream(conn net.Conn, in *bufio.Reader) {
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, in)
	_ = conn.Close()
}

// replies returns a session that writes stdout and stderr as Docker frames
// them and then ends the command.
func replies(stdout, stderr string) func(net.Conn, *bufio.Reader) {
	return func(conn net.Conn, _ *bufio.Reader) {
		if stdout != "" {
			_, _ = stdcopy.NewStdWriter(conn, stdcopy.Stdout).Write([]byte(stdout))
		}
		if stderr != "" {
			_, _ = stdcopy.NewStdWriter(conn, stdcopy.Stderr).Write([]byte(stderr))
		}
	}
}

// nextCreate waits for the next exec create the daemon receives.
func (d *execDaemon) nextCreate(t *testing.T) container.ExecOptions {
	t.Helper()
	select {
	case opts := <-d.created:
		return opts
	case <-time.After(5 * time.Second):
		t.Fatal("no exec was created")
		return container.ExecOptions{}
	}
}
