package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openbloxd.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadResolvesProfileIntoSpec(t *testing.T) {
	path := writeConfig(t, `
socket: /run/openbloxd/openbloxd.sock
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
    runtime: runsc
    egress: none
    user: "1000:1000"
    cpus: 2
    memory_mb: 2048
    disk_mb: 1024
    max_processes: 256
    idle_timeout: 30m
    max_age: 4h
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	spec := sandbox.NewSpec(cfg.Profiles["code-exec"].Options()...)
	if spec.Runtime != "runsc" || spec.Egress != sandbox.EgressNone {
		t.Errorf("spec runtime/egress = %q/%v", spec.Runtime, spec.Egress)
	}
	if spec.Resources.MemoryBytes != 2048<<20 || spec.Resources.DiskBytes != 1024<<20 {
		t.Errorf("resources = %+v", spec.Resources)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    privileged: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown profile field")
	}
}

func TestLoadRejectsDiskExceedingMemory(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    memory_mb: 512
    disk_mb: 1024
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: disk exceeds memory")
	}
}

func TestLoadRejectsNoProfiles(t *testing.T) {
	path := writeConfig(t, "socket: /tmp/s.sock\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: no profiles configured")
	}
}
