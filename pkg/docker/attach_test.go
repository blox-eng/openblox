package docker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/docker/docker/client"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// fakeDaemon answers just enough of Docker's API to drive attach: exec create
// succeeds, exec start is refused with a 409, and inspect reports the
// container as "running", "stopped" or "gone".
func fakeDaemon(t *testing.T, container string) *dockerSandbox {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"exec1"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec/exec1/start"):
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"container is not running"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/json"):
			switch container {
			case "running":
				_, _ = w.Write([]byte(`{"Id":"c1","State":{"Running":true}}`))
			case "stopped":
				_, _ = w.Write([]byte(`{"Id":"c1","State":{"Running":false,"Status":"exited"}}`))
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"No such container: c1"}`))
			}
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
	return &dockerSandbox{cli: cli, id: "c1", info: sandbox.Info{Name: "box"}}
}

// A memory kill under gVisor stops the sandbox a moment before Docker's state
// catches up, so an exec can be created and then refused at start with a 409.
// The Docker client reports that as a plain error with no type to match, so it
// is classified by asking the daemon what state the container is in.
func TestAttachRefusedBecauseTheContainerStoppedReportsStopped(t *testing.T) {
	s := fakeDaemon(t, "stopped")

	_, _, err := s.attach(context.Background(), sandbox.Command{Argv: []string{"true"}}, "")
	if !errors.Is(err, sandbox.ErrStopped) {
		t.Fatalf("attach = %v, want ErrStopped", err)
	}
}

// The container can also be removed between exec create and start, which the
// lifetime sweep can do.
func TestAttachRefusedBecauseTheContainerWasRemovedReportsNotFound(t *testing.T) {
	s := fakeDaemon(t, "gone")

	_, _, err := s.attach(context.Background(), sandbox.Command{Argv: []string{"true"}}, "")
	if !errors.Is(err, sandbox.ErrNotFound) {
		t.Fatalf("attach = %v, want ErrNotFound", err)
	}
}

// A start failure while the container still reports running is not a stopped
// sandbox. It stays an ordinary error rather than being mislabelled.
func TestAttachRefusedWhileTheContainerRunsStaysAnError(t *testing.T) {
	s := fakeDaemon(t, "running")

	_, _, err := s.attach(context.Background(), sandbox.Command{Argv: []string{"true"}}, "")
	if err == nil || errors.Is(err, sandbox.ErrStopped) || errors.Is(err, sandbox.ErrNotFound) {
		t.Fatalf("attach = %v, want an unclassified error", err)
	}
}
