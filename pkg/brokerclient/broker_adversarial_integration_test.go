//go:build integration

// Lifecycle failures that only exist once a broker sits between the caller and
// Docker: the daemon restarting under live sandboxes, a caller disconnecting
// mid-command, and output large enough to matter on the wire.
package brokerclient_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/internal/daemon"
	"github.com/blox-eng/openblox/pkg/brokerclient"
	"github.com/blox-eng/openblox/pkg/docker"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// serveBroker runs a daemon on socket until the returned stop is called.
func serveBroker(t *testing.T, socket string) (stop func()) {
	t.Helper()
	cfg := &daemon.Config{
		Socket:       socket,
		ReapInterval: time.Hour,
		Profiles: map[string]daemon.Profile{
			"test": {Image: testImage, Runtime: "runsc", Egress: "none", User: "1000:1000"},
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
	return func() {
		_ = srv.Close()
		_ = backend.Close()
	}
}

// The daemon keeps no state, so restarting it must neither lose nor orphan a
// sandbox: the container is the state, and a fresh daemon finds it by name.
func TestBrokerSandboxesSurviveADaemonRestart(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "openbloxd.sock")
	ctx := context.Background()
	const name = "openblox-broker-restart"

	// Cleaned up through Docker directly: the daemons this test starts are
	// stopped by the time cleanups run.
	direct, err := docker.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = direct.Destroy(context.Background(), name)
		_ = direct.Close()
	})

	stop := serveBroker(t, socket)
	c, err := brokerclient.New(socket)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := c.Create(ctx, name, brokerclient.WithProfile("test"))
	if err != nil {
		stop()
		t.Fatalf("Create = %v", err)
	}
	if err := sb.WriteFile(ctx, "/workspace/kept", 0o644, strings.NewReader("survives")); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}
	stop()
	_ = c.Close()

	stop = serveBroker(t, socket)
	defer stop()
	c, err = brokerclient.New(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	again, err := c.Open(ctx, name)
	if err != nil {
		t.Fatalf("Open after restart = %v", err)
	}
	rc, err := again.ReadFile(ctx, "/workspace/kept")
	if err != nil {
		t.Fatalf("ReadFile after restart = %v", err)
	}
	defer rc.Close()
	if body, _ := io.ReadAll(rc); string(body) != "survives" {
		t.Errorf("file after restart = %q, want %q", body, "survives")
	}
}

// A caller that disconnects mid-command must not leave the command running:
// the daemon's request context is cancelled, and that must reach the guest.
func TestBrokerClientDisconnectKillsTheCommand(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-broker-disconnect")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sleep", "3137"}}); err == nil {
		t.Fatal("Exec returned without error despite the caller giving up")
	}

	// The daemon learns of the disconnect asynchronously; give it a moment.
	var out string
	for range 20 {
		res, err := sb.Exec(context.Background(), sandbox.Command{Argv: []string{"sh", "-c",
			`n=0; for f in /proc/[0-9]*/cmdline; do tr '\0' ' ' 2>/dev/null <"$f" | grep -q '[s]leep 3137' && n=$((n+1)); done; echo $n`}})
		if err != nil {
			t.Fatalf("probe = %v", err)
		}
		if out = strings.TrimSpace(string(res.Stdout)); out == "0" {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Errorf("%s processes still running after the caller disconnected", out)
}

func TestBrokerReportsTruncatedOutput(t *testing.T) {
	c := startBroker(t)
	sb := create(t, c, "openblox-broker-flood")

	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c", "head -c 40000000 /dev/zero"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if !res.Truncated || len(res.Stdout) != sandbox.MaxOutputBytes {
		t.Errorf("Truncated = %v with %d bytes; want true with %d", res.Truncated, len(res.Stdout), sandbox.MaxOutputBytes)
	}
}

// Root must be refused at the broker too — by the profile's config validation
// in practice, and by the library underneath if a Config is built in code.
func TestBrokerRefusesARootProfile(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "openbloxd.sock")
	backend, err := docker.New()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ln, err := daemon.Listen(socket, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &daemon.Config{Socket: socket, Profiles: map[string]daemon.Profile{
		"root": {Image: testImage, User: "0:0"},
	}}
	srv := &http.Server{Handler: daemon.New(backend, cfg).Handler()}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	c, err := brokerclient.New(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Create(context.Background(), "openblox-broker-root", brokerclient.WithProfile("root"))
	if !errors.Is(err, sandbox.ErrInvalid) {
		_ = c.Destroy(context.Background(), "openblox-broker-root")
		t.Fatalf("Create under a root profile = %v, want ErrInvalid", err)
	}
}
