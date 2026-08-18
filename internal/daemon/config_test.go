package daemon

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoadRejectsNegativeIdleTimeout(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    idle_timeout: -1s
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error: negative idle_timeout silently disables reaping")
	}
	if !strings.Contains(err.Error(), "idle_timeout") {
		t.Errorf("error %q should name the offending field", err)
	}
}

// Each bound is individually sane, which is why per-field checks miss this:
// only the pair is wrong. A default above the maximum means every exec is
// clamped below the default the operator wrote, so the profile never once
// behaves as configured.
func TestLoadRejectsDefaultTimeoutAboveMaxTimeout(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    default_timeout: 10m
    max_timeout: 1m
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error: default_timeout above max_timeout clamps every command below its own default")
	}
	if !strings.Contains(err.Error(), "default_timeout") || !strings.Contains(err.Error(), "max_timeout") {
		t.Errorf("error %q should name both offending fields", err)
	}
}

func TestLoadRejectsNegativeMaxAge(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    max_age: -1h
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: negative max_age silently disables reaping")
	}
}

func TestLoadRejectsNegativeMemory(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    memory_mb: -1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error: negative memory_mb is an operator typo, not a request for the library default")
	}
	if !strings.Contains(err.Error(), "memory_mb") {
		t.Errorf("error %q should name the offending field", err)
	}
}

func TestLoadRejectsNegativeCPUs(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    cpus: -2
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: negative cpus")
	}
}

func TestLoadRejectsNoProfiles(t *testing.T) {
	path := writeConfig(t, "socket: /tmp/s.sock\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: no profiles configured")
	}
}

func TestLoadRejectsConflictingRegistryAuth(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
    registry_auth:
      username: alice
      password: one
  browser:
    image: example.com/browser@sha256:def
    registry_auth:
      username: bob
      password: two
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: profiles specify different registry_auth, but one Docker connection carries one credential")
	}
}

func TestLoadAcceptsMatchingRegistryAuth(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
    registry_auth:
      username: alice
      password: one
  browser:
    image: example.com/browser@sha256:def
    registry_auth:
      username: alice
      password: one
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Profiles["code-exec"].RegistryAuth.Username != "alice" {
		t.Errorf("registry auth not preserved: %+v", cfg.Profiles["code-exec"].RegistryAuth)
	}
}

func TestLoadAcceptsListenBlock(t *testing.T) {
	path := writeConfig(t, `
socket: /run/openbloxd/openbloxd.sock
listen:
  address: "127.0.0.1:9443"
  tls:
    cert_file: /etc/openbloxd/tls/server.crt
    key_file: /etc/openbloxd/tls/server.key
    client_ca_file: /etc/openbloxd/tls/clients-ca.crt
    allowed_client_cns: ["sandbox-caller"]
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen == nil {
		t.Fatal("Listen is nil, want the parsed block")
	}
	if cfg.Listen.Address != "127.0.0.1:9443" {
		t.Errorf("Address = %q, want 127.0.0.1:9443", cfg.Listen.Address)
	}
	if got := cfg.Listen.TLS.AllowedClientCNs; len(got) != 1 || got[0] != "sandbox-caller" {
		t.Errorf("AllowedClientCNs = %v, want [sandbox-caller]", got)
	}
}

// A daemon with no listener of any kind would start and accept nothing, which
// looks identical to a working one until a caller times out.
func TestLoadRejectsNeitherSocketNorListen(t *testing.T) {
	path := writeConfig(t, `
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load succeeded with neither socket nor listen")
	}
	if !strings.Contains(err.Error(), "accept nothing") {
		t.Errorf("error = %v, want it to say the daemon would accept nothing", err)
	}
}

// The socket may be omitted, but only when a network listener replaces it.
func TestLoadAcceptsListenWithoutSocket(t *testing.T) {
	path := writeConfig(t, `
listen:
  address: "127.0.0.1:9443"
  tls:
    cert_file: /c
    key_file: /k
    client_ca_file: /ca
    allowed_client_cns: ["sandbox-caller"]
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

// Each of these is a refusal to start. A bind address that defaulted, or a
// listener that accepted any certificate its CA ever signed, is the failure
// this block exists to prevent.
func TestLoadRejectsIncompleteListenBlock(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"no address": {`
listen:
  tls:
    cert_file: /c
    key_file: /k
    client_ca_file: /ca
    allowed_client_cns: ["sandbox-caller"]
`, "address"},
		"no tls block": {`
listen:
  address: "127.0.0.1:9443"
`, "cert_file"},
		"address is not host:port": {`
listen:
  address: "127.0.0.1"
  tls:
    cert_file: /c
    key_file: /k
    client_ca_file: /ca
    allowed_client_cns: ["sandbox-caller"]
`, "host:port"},
		"no cert_file": {`
listen:
  address: "127.0.0.1:9443"
  tls:
    key_file: /k
    client_ca_file: /ca
    allowed_client_cns: ["sandbox-caller"]
`, "cert_file"},
		"no key_file": {`
listen:
  address: "127.0.0.1:9443"
  tls:
    cert_file: /c
    client_ca_file: /ca
    allowed_client_cns: ["sandbox-caller"]
`, "key_file"},
		"no client_ca_file": {`
listen:
  address: "127.0.0.1:9443"
  tls:
    cert_file: /c
    key_file: /k
    allowed_client_cns: ["sandbox-caller"]
`, "client_ca_file"},
		"no allowed_client_cns": {`
listen:
  address: "127.0.0.1:9443"
  tls:
    cert_file: /c
    key_file: /k
    client_ca_file: /ca
`, "allowed_client_cns"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, "socket: /run/s.sock\n"+tc.body+`
profiles:
  code-exec:
    image: example.com/sandbox@sha256:abc
`)
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load succeeded on an incomplete listen block")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

func TestIsWildcardHost(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:9443":   false,
		"0.0.0.0:9443":     true,
		":9443":            true,
		"[::]:9443":        true,
		"example.com:9443": false,
	}
	for addr, want := range cases {
		if got := (ListenConfig{Address: addr}).IsWildcardHost(); got != want {
			t.Errorf("IsWildcardHost(%q) = %v, want %v", addr, got, want)
		}
	}
}
