package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/client"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// The first three lines are Docker's own, from moby daemon/daemon_unix.go at
// v28.5.2 (verifyPlatformContainerResources). The fourth is a rewording, so a
// later engine that says it differently is still refused.
func TestDiscardedLimitIsRefused(t *testing.T) {
	cases := []struct {
		name     string
		warnings []string
		limit    string // "" means the warnings must not refuse
	}{
		{"pids", []string{"Your kernel does not support PIDs limit capabilities or the cgroup is not mounted. PIDs limit discarded."}, "pids"},
		{"memory", []string{"Your kernel does not support memory limit capabilities or the cgroup is not mounted. Limitation discarded."}, "memory"},
		{"swap", []string{"Your kernel does not support swap limit capabilities or the cgroup is not mounted. Memory limited without swap."}, "swap"},
		{"reworded", []string{"The PIDs limit was discarded by the daemon."}, "pids"},
		{"unrelated", []string{"The requested image's platform (linux/arm64) does not match the detected host platform (linux/amd64/v3) and no specific platform was requested"}, ""},
		{"none", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkLimitWarnings(c.warnings)
			if c.limit == "" {
				if err != nil {
					t.Fatalf("want no refusal, got %v", err)
				}
				return
			}
			if !errors.Is(err, sandbox.ErrRuntimeUnavailable) {
				t.Fatalf("want ErrRuntimeUnavailable, got %v", err)
			}
			for _, want := range []string{c.limit, "docs/security.md#rootless"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestDaemonWithoutCgroupsIsRefused(t *testing.T) {
	healthy := func() system.Info {
		return system.Info{
			CgroupDriver: "systemd",
			MemoryLimit:  true,
			SwapLimit:    true,
			PidsLimit:    true,
			CPUCfsQuota:  true,
			Runtimes:     map[string]system.RuntimeWithStatus{"runsc": {Runtime: system.Runtime{Path: "/usr/bin/runsc"}}, "runc": {Runtime: system.Runtime{Path: "runc"}}},
		}
	}
	rootless := func(i system.Info) system.Info {
		i.SecurityOptions = []string{"name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"}
		return i
	}
	cases := []struct {
		name    string
		info    system.Info
		runtime string
		want    string // "" means the daemon must be accepted
	}{
		{"healthy", healthy(), "runsc", ""},
		{"no cgroups", func() system.Info { i := healthy(); i.CgroupDriver = "none"; return i }(), "runsc", "cgroup"},
		{"no memory", func() system.Info { i := healthy(); i.MemoryLimit = false; return i }(), "runsc", "memory"},
		{"no swap", func() system.Info { i := healthy(); i.SwapLimit = false; return i }(), "runsc", "swap"},
		{"no pids", func() system.Info { i := healthy(); i.PidsLimit = false; return i }(), "runsc", "pids"},
		{"no cpu quota", func() system.Info { i := healthy(); i.CPUCfsQuota = false; return i }(), "runsc", "cpu"},
		{"rootless runsc", rootless(healthy()), "runsc", "rootless"},
		{"rootless runsc under another name", func() system.Info {
			i := rootless(healthy())
			i.Runtimes["gvisor"] = system.RuntimeWithStatus{Runtime: system.Runtime{Path: "/usr/local/bin/runsc"}}
			return i
		}(), "gvisor", "rootless"},
		{"rootless runc", rootless(healthy()), "runc", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkDaemonCaps(c.info, c.runtime)
			if c.want == "" {
				if err != nil {
					t.Fatalf("want the daemon accepted, got %v", err)
				}
				return
			}
			if !errors.Is(err, sandbox.ErrRuntimeUnavailable) {
				t.Fatalf("want ErrRuntimeUnavailable, got %v", err)
			}
			for _, want := range []string{c.want, "docs/security.md#rootless"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

// createDaemon answers the calls Create makes, and records each one.
type createDaemon struct {
	info     system.Info
	warnings []string

	mu      sync.Mutex
	calls   []string
	started bool
}

func (d *createDaemon) saw(call string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.calls {
		if c == call {
			return true
		}
	}
	return false
}

func newCreateDaemon(t *testing.T, d *createDaemon) *Backend {
	t.Helper()
	name := containerName("box")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path[strings.Index(r.URL.Path[1:], "/")+1:] // drop the /v1.45 prefix
		d.mu.Lock()
		switch {
		case r.Method == http.MethodGet && path == "/info":
			d.calls = append(d.calls, "info")
		case r.Method == http.MethodPost && path == "/containers/create":
			d.calls = append(d.calls, "create")
		case r.Method == http.MethodDelete && path == "/containers/c1":
			d.calls = append(d.calls, "delete force="+r.URL.Query().Get("force"))
		case r.Method == http.MethodPost && path == "/containers/c1/start":
			d.calls = append(d.calls, "start")
			d.started = true
		}
		started := d.started
		d.mu.Unlock()

		switch {
		case r.Method == http.MethodGet && path == "/containers/"+name+"/json":
			if !started {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"No such container"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":     "c1",
				"Config": map[string]any{"Image": "alpine:3.20", "Labels": map[string]string{labelManaged: "true", labelName: "box"}},
				"State":  map[string]any{"Status": "running", "Running": true},
			})
		case r.Method == http.MethodGet && path == "/info":
			_ = json.NewEncoder(w).Encode(d.info)
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/images/"):
			_, _ = w.Write([]byte(`{"Id":"sha256:abc"}`))
		case r.Method == http.MethodPost && path == "/containers/create":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "c1", "Warnings": d.warnings})
		case r.Method == http.MethodDelete && path == "/containers/c1",
			r.Method == http.MethodPost && path == "/containers/c1/start":
			w.WriteHeader(http.StatusNoContent)
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
	return &Backend{cli: cli}
}

func TestCreateRemovesAContainerWhoseLimitWasDiscarded(t *testing.T) {
	healthy := system.Info{
		CgroupDriver: "systemd", MemoryLimit: true, SwapLimit: true, PidsLimit: true, CPUCfsQuota: true,
		Runtimes: map[string]system.RuntimeWithStatus{"runsc": {Runtime: system.Runtime{Path: "/usr/bin/runsc"}}},
	}
	create := func(b *Backend) error {
		_, err := b.Create(context.Background(), "box", sandbox.WithImage("alpine:3.20"))
		return err
	}

	t.Run("discarded limit", func(t *testing.T) {
		d := &createDaemon{info: healthy, warnings: []string{"Your kernel does not support PIDs limit capabilities or the cgroup is not mounted. PIDs limit discarded."}}
		err := create(newCreateDaemon(t, d))
		if !errors.Is(err, sandbox.ErrRuntimeUnavailable) {
			t.Fatalf("want ErrRuntimeUnavailable, got %v", err)
		}
		if !d.saw("delete force=1") {
			t.Errorf("the created container was not removed; calls: %v", d.calls)
		}
		if d.saw("start") {
			t.Errorf("a sandbox whose limit was discarded was started; calls: %v", d.calls)
		}
	})

	t.Run("daemon without pids", func(t *testing.T) {
		info := healthy
		info.PidsLimit = false
		d := &createDaemon{info: info}
		if err := create(newCreateDaemon(t, d)); !errors.Is(err, sandbox.ErrRuntimeUnavailable) {
			t.Fatalf("want ErrRuntimeUnavailable, got %v", err)
		}
		if d.saw("create") {
			t.Errorf("a container was created on a daemon that cannot cap it; calls: %v", d.calls)
		}
	})

	t.Run("rootless runsc", func(t *testing.T) {
		info := healthy
		info.SecurityOptions = []string{"name=seccomp,profile=builtin", "name=rootless"}
		d := &createDaemon{info: info}
		if err := create(newCreateDaemon(t, d)); !errors.Is(err, sandbox.ErrRuntimeUnavailable) {
			t.Fatalf("want ErrRuntimeUnavailable, got %v", err)
		}
		if d.saw("create") {
			t.Errorf("a runsc container was created on a rootless daemon; calls: %v", d.calls)
		}
	})

	t.Run("healthy daemon", func(t *testing.T) {
		d := &createDaemon{info: healthy}
		if err := create(newCreateDaemon(t, d)); err != nil {
			t.Fatalf("create on a healthy daemon: %v", err)
		}
		if !d.saw("start") {
			t.Errorf("the sandbox was not started; calls: %v", d.calls)
		}
	})
}
