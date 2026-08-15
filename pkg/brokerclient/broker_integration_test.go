//go:build integration

// These tests re-run pkg/docker's integration assertions through openbloxd
// instead of talking to Docker directly, proving the broker behaves
// identically to the library it wraps. See CONTRIBUTING.md for the gVisor
// prerequisites. Run with: make test-integration
package brokerclient_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/internal/daemon"
	"github.com/blox-eng/openblox/pkg/brokerclient"
	"github.com/blox-eng/openblox/pkg/docker"
	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// testImage matches pkg/docker's integration suite, so the two run identical
// containers under identical isolation and any difference in outcome is the
// broker, not the image.
const testImage = "alpine:3.20"

// startBroker runs an openbloxd against the live Docker daemon on a socket in
// t.TempDir(), and returns a Client pointed at it. The daemon is in-process:
// the point is to exercise the wire and the policy, not the packaging.
func startBroker(t *testing.T, opts ...brokerclient.Option) *brokerclient.Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "openbloxd.sock")
	cfg := &daemon.Config{
		Socket:       socket,
		ReapInterval: time.Hour, // no sweeps mid-test
		Profiles: map[string]daemon.Profile{
			"test": {
				Image:        testImage,
				Runtime:      "runsc",
				Egress:       "none",
				User:         "1000:1000",
				CPUs:         2,
				MemoryMB:     2048,
				DiskMB:       1024,
				MaxProcesses: 256,
				IdleTimeout:  30 * time.Minute,
				MaxAge:       time.Hour,
			},
		},
	}
	backend, err := docker.New()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := daemon.Listen(socket, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: daemon.New(backend, cfg).Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = backend.Close()
	})

	c, err := brokerclient.New(socket, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// create makes a sandbox under the "test" profile and guarantees it is
// destroyed even if the test fails.
func create(t *testing.T, c *brokerclient.Client, name string) sandbox.Sandbox {
	t.Helper()
	ctx := context.Background()
	sb, err := c.Create(ctx, name, brokerclient.WithProfile("test"))
	if err != nil {
		t.Fatalf("Create(%q) = %v", name, err)
	}
	t.Cleanup(func() { _ = c.Destroy(context.Background(), name) })
	return sb
}

// --- create then exec then read output (pkg/docker/sandbox_integration_test.go) ---

func TestBrokerExecCapturesStdoutStderrAndExitCode(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-exec")
	ctx := context.Background()

	res, err := sb.Exec(ctx, sandbox.Command{
		Argv: []string{"sh", "-c", "echo out; echo err 1>&2; exit 3"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}

	if got := strings.TrimSpace(string(res.Stdout)); got != "out" {
		t.Errorf("stdout = %q, want %q", got, "out")
	}
	if got := strings.TrimSpace(string(res.Stderr)); got != "err" {
		t.Errorf("stderr = %q, want %q — streams are not demultiplexed", got, "err")
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.ExitCode)
	}
}

func TestBrokerExecRunsWithoutAShell(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-noshell")

	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"echo", "a; echo b"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "a; echo b" {
		t.Errorf("stdout = %q, want the literal argument — argv reached a shell", got)
	}
}

func TestBrokerExecRejectsInvalidCommand(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-badcmd")

	if _, err := sb.Exec(context.Background(), sandbox.Command{}); !errors.Is(err, sandbox.ErrInvalid) {
		t.Errorf("Exec with no argv = %v, want ErrInvalid", err)
	}
}

// --- write then read a file ---

func TestBrokerFileRoundTrip(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-files")
	ctx := context.Background()

	want := []byte("line one\nline two\n")
	if err := sb.WriteFile(ctx, "/workspace/nested/dir/data.txt", 0o644, bytes.NewReader(want)); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	rc, err := sb.ReadFile(ctx, "/workspace/nested/dir/data.txt")
	if err != nil {
		t.Fatalf("ReadFile = %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round trip = %q, want %q", got, want)
	}
}

func TestBrokerReadFileAbsentReportsNotFound(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-readmissing")

	_, err := sb.ReadFile(context.Background(), "/workspace/nope.txt")
	if !errors.Is(err, sandbox.ErrNotFound) {
		t.Errorf("ReadFile(absent) = %v, want ErrNotFound", err)
	}
}

func TestBrokerWriteFileRejectsRelativePath(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-relpath")

	err := sb.WriteFile(context.Background(), "relative/path.txt", 0o644, strings.NewReader("x"))
	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Errorf("WriteFile(relative) = %v, want ErrInvalid", err)
	}
}

// --- start a background process and observe it ---

// StartProcess must return once the process is detached, not once it exits.
func TestBrokerStartProcessDetaches(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-startproc")
	ctx := context.Background()

	start := time.Now()
	err := sb.StartProcess(ctx, "sleeper", sandbox.Command{Argv: []string{"sleep", "60"}})
	if err != nil {
		t.Fatalf("StartProcess = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("StartProcess took %s; it waited for the process instead of detaching", elapsed)
	}

	res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "ps -o args | grep -c '[s]leep 60'"}})
	if err != nil {
		t.Fatalf("Exec ps = %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) == "0" {
		t.Error("no sleep process running; StartProcess did not leave it behind")
	}
}

func TestBrokerStartProcessIsIdempotent(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-startproc-idem")
	ctx := context.Background()

	cmd := sandbox.Command{Argv: []string{"sleep", "60"}}
	for i := range 3 {
		if err := sb.StartProcess(ctx, "sleeper", cmd); err != nil {
			t.Fatalf("StartProcess #%d = %v", i+1, err)
		}
	}

	res, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "ps -o args | grep -c '[s]leep 60'"}})
	if err != nil {
		t.Fatalf("Exec ps = %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "1" {
		t.Errorf("%s sleep processes running, want 1 — StartProcess started duplicates", got)
	}
}

func TestBrokerStartProcessCapturesOutput(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-test-broker-startproc-log")
	ctx := context.Background()

	err := sb.StartProcess(ctx, "greeter", sandbox.Command{
		Argv: []string{"sh", "-c", "echo hello from the background"},
	})
	if err != nil {
		t.Fatalf("StartProcess = %v", err)
	}
	waitFor(t, sb, "grep -q hello /tmp/.openblox/proc/greeter/log")
}

// waitFor polls a shell condition inside the sandbox until it holds.
func waitFor(t *testing.T, sb sandbox.Sandbox, condition string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		res, err := sb.Exec(context.Background(), sandbox.Command{Argv: []string{"sh", "-c", condition}})
		if err != nil {
			t.Fatalf("Exec %q = %v", condition, err)
		}
		if res.ExitCode == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition never held: %s", condition)
}

// --- expose a port and fetch through the preview handler ---

func previewKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, preview.MinKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key = %v", err)
	}
	return key
}

// serveInSandbox stands up an HTTP server on the sandbox's loopback interface
// and returns once it is answering. See pkg/docker/preview_integration_test.go
// for why nc rather than a real server.
func serveInSandbox(t *testing.T, sb sandbox.Sandbox, body string) {
	t.Helper()
	ctx := context.Background()

	response := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	if err := sb.WriteFile(ctx, "/workspace/response.http", 0o644, strings.NewReader(response)); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	err := sb.StartProcess(ctx, "server", sandbox.Command{
		Argv: []string{"sh", "-c",
			"while :; do nc -l -p 8080 < /workspace/response.http > /dev/null 2>&1; done"},
	})
	if err != nil {
		t.Fatalf("StartProcess = %v", err)
	}
	waitFor(t, sb, "wget -q -T2 -O- http://127.0.0.1:8080/ >/dev/null 2>&1")
}

// End to end: Expose mints a credential, the handler validates it, and the
// traffic reaches a port that has no route to it — driven through the broker
// instead of docker.Backend directly. c.PreviewHandler() is used rather than
// building a second preview.NewHandler(c, signer): only the instance the
// Client itself built is the one Revoke (below) can reach — see
// brokerclient.WithPreviews's doc comment.
func TestBrokerPreviewServesAnExposedPort(t *testing.T) {
	key := previewKey(t)
	c := startBroker(t, brokerclient.WithPreviews(key, "https://previews.test"))

	name := "openblox-test-broker-preview"
	sb := create(t, c, name)
	ctx := context.Background()

	serveInSandbox(t, sb, "<h1>previewed</h1>")

	p, err := sb.Expose(ctx, 8080, time.Minute)
	if err != nil {
		t.Fatalf("Expose = %v", err)
	}
	if !strings.HasPrefix(p.URL, "https://previews.test/preview/") {
		t.Errorf("URL = %q, want it under the configured base", p.URL)
	}
	if p.Token == "" {
		t.Fatal("Expose returned no token")
	}
	if strings.Contains(p.URL, p.Token) {
		t.Error("the token is embedded in the URL, where it leaks into logs and history")
	}

	srv := httptest.NewServer(c.PreviewHandler())
	defer srv.Close()

	body, status := previewGet(t, srv.URL+preview.RoutePrefix+"/"+name+"/8080/index.html", p.Token)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", status, body)
	}
	if !strings.Contains(body, "previewed") {
		t.Errorf("body = %q, want the page served inside the sandbox", body)
	}

	// And without the credential, nothing.
	_, status = previewGet(t, srv.URL+preview.RoutePrefix+"/"+name+"/8080/index.html", "")
	if status != http.StatusUnauthorized {
		t.Errorf("status without a token = %d, want 401", status)
	}

	// Revoke closes it before expiry.
	if err := sb.Revoke(ctx, 8080, p.Token); err != nil {
		t.Fatalf("Revoke = %v", err)
	}
	_, status = previewGet(t, srv.URL+preview.RoutePrefix+"/"+name+"/8080/index.html", p.Token)
	if status != http.StatusUnauthorized {
		t.Errorf("status after revoke = %d, want 401", status)
	}
}

func TestBrokerExposeWithoutConfigurationFails(t *testing.T) {
	c := startBroker(t) // no WithPreviews
	sb := create(t, c, "openblox-test-broker-preview-unconfigured")

	if _, err := sb.Expose(context.Background(), 8080, time.Minute); err == nil {
		t.Error("Expose succeeded on a client with no preview configuration")
	}
}

func previewGet(t *testing.T, url, token string) (body string, status int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest = %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s = %v", url, err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.String(), resp.StatusCode
}

// --- destroy is idempotent ---

func TestBrokerOpenAndDestroy(t *testing.T) {
	c := startBroker(t)
	ctx := context.Background()
	name := "openblox-test-broker-lifecycle"

	create(t, c, name)

	if _, err := c.Open(ctx, name); err != nil {
		t.Fatalf("Open after Create = %v", err)
	}
	if err := c.Destroy(ctx, name); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	if _, err := c.Open(ctx, name); !errors.Is(err, sandbox.ErrNotFound) {
		t.Errorf("Open after Destroy = %v, want ErrNotFound", err)
	}
	// Idempotent: destroying an absent sandbox is not an error.
	if err := c.Destroy(ctx, name); err != nil {
		t.Errorf("second Destroy = %v, want nil", err)
	}
}

// --- broker-specific: policy options are refused before anything is created ---

func TestBrokerRefusesPolicyOptionsAgainstALiveDaemon(t *testing.T) {
	c := startBroker(t)
	_, err := c.Create(context.Background(), "x",
		brokerclient.WithProfile("test"), sandbox.WithRuntime("runc"))
	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if _, err := c.Open(context.Background(), "x"); !errors.Is(err, sandbox.ErrNotFound) {
		t.Error("a refused create must not have created anything")
	}
}

// --- label round trip: Task 10 restored Info.Labels across the wire; this is
// the one test that drives a real daemon and a real client together instead
// of asserting each side of the seam in isolation. ---

func TestBrokerLabelRoundTrip(t *testing.T) {
	c := startBroker(t)
	ctx := context.Background()
	name := "openblox-test-broker-labels"

	sb, err := c.Create(ctx, name, brokerclient.WithProfile("test"), sandbox.WithLabel("caller-key", "caller-value"))
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	t.Cleanup(func() { _ = c.Destroy(context.Background(), name) })

	got := sb.Info().Labels
	if got["caller-key"] != "caller-value" {
		t.Errorf("Labels[caller-key] = %q, want %q", got["caller-key"], "caller-value")
	}
	// The daemon's own bookkeeping label must not leak into the caller's
	// namespace — it is reported separately (as the profile choice), and a
	// caller iterating Labels should see only what it set.
	if _, ok := got["openbloxd.profile"]; ok {
		t.Errorf("Labels leaked the daemon's own marker: %v", got)
	}

	// Re-fetch through Open to prove the round trip survives a fresh request,
	// not just the value handed back from Create.
	reopened, err := c.Open(ctx, name)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	got = reopened.Info().Labels
	if got["caller-key"] != "caller-value" {
		t.Errorf("Open: Labels[caller-key] = %q, want %q", got["caller-key"], "caller-value")
	}
	if _, ok := got["openbloxd.profile"]; ok {
		t.Errorf("Open: Labels leaked the daemon's own marker: %v", got)
	}
}
