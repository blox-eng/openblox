package brokerclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// newTestClient starts an httptest.Server on a Unix socket in t.TempDir()
// with the given handler, and points a Client at it. A nil handler means the
// test expects no request to reach the daemon at all — Create should fail
// client-side before ever dialing. Extra opts (e.g. WithPreviews) pass
// straight through to New.
func newTestClient(t *testing.T, handler http.HandlerFunc, opts ...Option) *Client {
	t.Helper()

	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request reached the daemon: %s %s", r.Method, r.URL.Path)
		}
	}
	return newTestClientMux(t, handler, opts...)
}

// newTestClientMux is the shared plumbing behind newTestClient: it also
// backs the tests that need a real mux to prove the client hits the daemon's
// actual route shapes rather than a single catch-all handler.
func newTestClientMux(t *testing.T, handler http.Handler, opts ...Option) *Client {
	t.Helper()

	sockPath := filepath.Join(t.TempDir(), "openbloxd.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}

	srv := httptest.NewUnstartedServer(handler)
	// Swap in the Unix listener before starting: NewUnstartedServer opens its
	// own TCP one that this test has no use for.
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	c, err := New(sockPath, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// respondJSON writes a JSON body with the given status, the shape every
// openbloxd handler responds with.
func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func TestCreateRejectsPolicyBearingOptions(t *testing.T) {
	c := newTestClient(t, nil)
	cases := []struct {
		name string
		opt  sandbox.CreateOption
		want string
	}{
		{"runtime", sandbox.WithRuntime("runc"), "runtime"},
		{"egress", sandbox.WithEgress(sandbox.EgressUnrestricted), "egress"},
		{"image", sandbox.WithImage("evil.example.com/x"), "image"},
		{"user", sandbox.WithUser("0:0"), "user"},
		{"resources", sandbox.WithResources(sandbox.Resources{CPUs: 4}), "resources"},
		{"lifetime", sandbox.WithLifetime(sandbox.Lifetime{MaxAge: time.Hour}), "lifetime"},
		{"timeouts", sandbox.WithCommandTimeouts(5*time.Second, 30*time.Second), "timeouts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Create(context.Background(), "a", WithProfile("code-exec"), tc.opt)
			if !errors.Is(err, sandbox.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %q should name %q", err, tc.want)
			}
		})
	}
}

func TestCreateRequiresProfile(t *testing.T) {
	c := newTestClient(t, nil)
	if _, err := c.Create(context.Background(), "a"); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestCreateAllowsEnvAndLabels(t *testing.T) {
	var got brokerapi.CreateRequest
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		respondJSON(w, http.StatusCreated, brokerapi.Info{Name: "a", State: "running"})
	})
	if _, err := c.Create(context.Background(), "a",
		WithProfile("code-exec"),
		sandbox.WithEnv("K=v"),
		sandbox.WithLabel("tenant", "t1"),
	); err != nil {
		t.Fatal(err)
	}
	if got.Profile != "code-exec" || len(got.Env) != 1 || got.Labels["tenant"] != "t1" {
		t.Errorf("request = %+v", got)
	}
	// The profile label is internal bookkeeping and must never reach the
	// wire — it would collide with the daemon's own reserved label.
	if _, ok := got.Labels[profileLabel]; ok {
		t.Errorf("request labels leaked %q: %+v", profileLabel, got.Labels)
	}
}

// TestLabelsRoundTripThroughInfo is the client-side half of the label round
// trip: whatever the wire Info carries in Labels must surface on
// sb.Info().Labels — this used to be silently dropped, the same class of bug
// Create's policy-field rejection exists to prevent for CreateOptions.
func TestLabelsRoundTripThroughInfo(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req brokerapi.CreateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Respond the way the daemon actually does: caller labels back,
		// openbloxd.profile never included (it is reported as Profile).
		respondJSON(w, http.StatusCreated, brokerapi.Info{
			Name: "a", State: "running", Profile: req.Profile, Labels: req.Labels,
		})
	})
	sb, err := c.Create(context.Background(), "a", WithProfile("code-exec"), sandbox.WithLabel("tenant", "t1"))
	if err != nil {
		t.Fatal(err)
	}
	if sb.Info().Labels["tenant"] != "t1" {
		t.Errorf("Info().Labels = %+v, want tenant=t1", sb.Info().Labels)
	}
	if _, ok := sb.Info().Labels[profileLabel]; ok {
		t.Errorf("Info().Labels leaked %q: %+v", profileLabel, sb.Info().Labels)
	}
}

func TestErrorKindMapsBackToSentinel(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, http.StatusNotFound, brokerapi.Error{Message: "nope", Kind: brokerapi.KindNotFound})
	})
	_, err := c.Open(context.Background(), "a")
	if !errors.Is(err, sandbox.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListDecodesEveryEntry(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/sandboxes" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		respondJSON(w, http.StatusOK, []brokerapi.Info{
			{Name: "a", State: "running"},
			{Name: "b", State: "stopped"},
		})
	})
	infos, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 || infos[0].Name != "a" || infos[1].State != sandbox.StateStopped {
		t.Errorf("infos = %+v", infos)
	}
}

func TestDestroyIsIdempotent(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/sandboxes/a" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.Destroy(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
}

func TestExposeFailsWithoutPreviewsConfigured(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, http.StatusCreated, brokerapi.Info{Name: "a", State: "running"})
	})
	sb, err := c.Create(context.Background(), "a", WithProfile("code-exec"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Expose(context.Background(), 8080, 0); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

// TestSandboxMethodsHitTheDaemonRoutes exercises Exec, WriteFile, ReadFile,
// StartProcess and Stop against a mux shaped like the daemon's own route
// table (internal/daemon/server.go), to prove the client builds the paths
// and bodies that server actually expects — not just that some handler
// answers 200.
func TestSandboxMethodsHitTheDaemonRoutes(t *testing.T) {
	var wroteBody []byte
	var execReq brokerapi.ExecRequest
	var procReq brokerapi.ProcessRequest

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sandboxes", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusCreated, brokerapi.Info{Name: "a", State: "running"})
	})
	mux.HandleFunc("POST /sandboxes/{name}/exec", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") != "a" {
			t.Errorf("name = %q", r.PathValue("name"))
		}
		_ = json.NewDecoder(r.Body).Decode(&execReq)
		respondJSON(w, http.StatusOK, brokerapi.ExecResponse{Stdout: []byte("hi"), ExitCode: 0})
	})
	mux.HandleFunc("PUT /sandboxes/{name}/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
		// net/http decodes the percent-encoded leading slash back into the
		// wildcard value, so what the handler sees is the caller's original
		// absolute path, not the wire-safe "%2Fworkspace/..." on the URL line.
		if got := r.PathValue("path"); got != "/workspace/main.go" {
			t.Errorf("path = %q", got)
		}
		var err error
		wroteBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /sandboxes/{name}/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("path"); got != "/workspace/main.go" {
			t.Errorf("path = %q", got)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("package main"))
	})
	mux.HandleFunc("POST /sandboxes/{name}/processes", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&procReq)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /sandboxes/{name}/stop", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	c := newTestClientMux(t, mux)
	sb, err := c.Create(context.Background(), "a", WithProfile("code-exec"))
	if err != nil {
		t.Fatal(err)
	}

	res, err := sb.Exec(context.Background(), sandbox.Command{Argv: []string{"echo", "hi"}})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(res.Stdout) != "hi" || len(execReq.Argv) != 2 {
		t.Errorf("Exec result = %+v, req = %+v", res, execReq)
	}

	if err := sb.WriteFile(context.Background(), "/workspace/main.go", 0o644, strings.NewReader("package main")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if string(wroteBody) != "package main" {
		t.Errorf("wroteBody = %q", wroteBody)
	}

	rc, err := sb.ReadFile(context.Background(), "/workspace/main.go")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "package main" {
		t.Errorf("read = %q", got)
	}

	if err := sb.StartProcess(context.Background(), "watcher", sandbox.Command{Argv: []string{"tail", "-f", "/dev/null"}}); err != nil {
		t.Fatalf("StartProcess: %v", err)
	}
	if procReq.Name != "watcher" || len(procReq.Argv) != 3 {
		t.Errorf("procReq = %+v", procReq)
	}

	if err := sb.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestExecRejectsStdin(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, http.StatusCreated, brokerapi.Info{Name: "a", State: "running"})
	})
	sb, err := c.Create(context.Background(), "a", WithProfile("code-exec"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sb.Exec(context.Background(), sandbox.Command{
		Argv:  []string{"cat"},
		Stdin: strings.NewReader("x"),
	})
	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestExposeAndRevokeRoundTripLocally(t *testing.T) {
	key := make([]byte, 32)
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, http.StatusCreated, brokerapi.Info{Name: "a", State: "running"})
	}, WithPreviews(key, "https://preview.example.com"))

	sb, err := c.Create(context.Background(), "a", WithProfile("code-exec"))
	if err != nil {
		t.Fatal(err)
	}

	pv, err := sb.Expose(context.Background(), 8080, 0)
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	if pv.Token == "" || pv.Port != 8080 {
		t.Fatalf("preview = %+v", pv)
	}
	if err := sb.Revoke(context.Background(), 8080, pv.Token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// A token minted for a different sandbox must not verify against this one.
	other := c.sandboxFrom(brokerapi.Info{Name: "b", State: "running"})
	if err := other.Revoke(context.Background(), 8080, pv.Token); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid for a token issued to a different sandbox", err)
	}
}
