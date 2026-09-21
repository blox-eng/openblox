# openbloxd Remote Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let openbloxd serve a network listener authenticated by mTLS, so the daemon can run on a host of its own, without weakening anything about the Unix socket deployment.

**Architecture:** A new optional `listen` block adds a TCP listener wrapped in TLS that requires a client certificate, verifies it against a configured CA, and additionally checks its Common Name against an explicit allowlist. Both listeners feed one `http.Server` with one handler, so no route table can drift between transports. A middleware records the caller's identity on every request context regardless of transport.

**Tech Stack:** Go 1.25, stdlib only (`crypto/tls`, `crypto/x509`, `net/http`). No new dependencies.

**Spec:** `specs/2026-08-18-openbloxd-remote-transport-design.md`

## Global Constraints

- **The Unix socket is unchanged and stays the default.** No existing deployment may acquire a certificate requirement. `Listen(socketPath, group)` keeps its exact signature and behaviour.
- **`brokerclient.New(socketPath string, opts ...Option)` keeps its exact signature.** Remote is a second constructor, never a change to this one.
- **No configuration field added by this plan has a default.** Every one of them is a refusal to start when `listen` is present. A bind address in particular must never be defaulted.
- **`allowed_client_cns` is mandatory and must be non-empty** whenever `listen` is set. Certificate verification alone would make the CA the entire access control list.
- **No new module dependencies.** `go.mod` must be unchanged by this work.
- **TLS 1.3 minimum** on both the daemon and client halves.
- **`*tls.Config` must not appear in any exported `brokerclient` signature.** The client takes file paths so that an unverified client is inexpressible rather than rejected at runtime.
- **Documentation placeholders are neutral** — `127.0.0.1`, `example.com`, `sandbox-caller`. Match the repository's existing convention.
- **Conventional commits.** The squashed PR title must be `feat(daemon): ...` — a `chore:` or `refactor:` title produces no release at all.

---

### Task 1: The `listen` configuration block and its refusals

**Files:**
- Modify: `internal/daemon/config.go`
- Modify: `internal/daemon/config_test.go`
- Modify: `deploy/openbloxd.example.yaml`

**Interfaces:**
- Consumes: nothing.
- Produces: `daemon.ListenConfig{Address string, TLS TLSConfig}`, `daemon.TLSConfig{CertFile, KeyFile, ClientCAFile string, AllowedClientCNs []string}`, `Config.Listen *ListenConfig`, and `func (l ListenConfig) IsWildcardHost() bool`. Tasks 2 and 4 depend on all of these.

- [ ] **Step 1: Write the failing tests**

Add to `internal/daemon/config_test.go`:

```go
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
		"127.0.0.1:9443": false,
		"0.0.0.0:9443":   true,
		":9443":          true,
		"[::]:9443":      true,
		"example.com:9443": false,
	}
	for addr, want := range cases {
		if got := (ListenConfig{Address: addr}).IsWildcardHost(); got != want {
			t.Errorf("IsWildcardHost(%q) = %v, want %v", addr, got, want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/daemon/ -run 'TestLoadAcceptsListen|TestLoadRejects|TestIsWildcardHost' -v`
Expected: FAIL — compile error, `cfg.Listen` undefined and `ListenConfig` undefined.

- [ ] **Step 3: Add the types**

In `internal/daemon/config.go`, add `"net"` to the imports, add the `Listen` field to `Config`, and add the two new types after it:

```go
type Config struct {
	Socket       string             `yaml:"socket"`
	SocketGroup  string             `yaml:"socket_group"`
	Listen       *ListenConfig      `yaml:"listen"`
	ReapInterval time.Duration      `yaml:"reap_interval"`
	Profiles     map[string]Profile `yaml:"profiles"`
}

// ListenConfig is the network listener. Absent means the daemon serves only
// its Unix socket, which stays the default and the recommended arrangement
// wherever caller and daemon share a host.
type ListenConfig struct {
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
}

// TLSConfig is the daemon's half of the mTLS credential, plus the allowlist
// that stops the CA from being the whole access control list.
type TLSConfig struct {
	CertFile         string   `yaml:"cert_file"`
	KeyFile          string   `yaml:"key_file"`
	ClientCAFile     string   `yaml:"client_ca_file"`
	AllowedClientCNs []string `yaml:"allowed_client_cns"`
}

// IsWildcardHost reports whether the address binds every interface. That is a
// legitimate choice for a daemon whose network namespace is already the
// boundary, and a serious mistake otherwise — so it is warned about at boot
// rather than refused.
func (l ListenConfig) IsWildcardHost() bool {
	host, _, err := net.SplitHostPort(l.Address)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
```

- [ ] **Step 4: Replace the socket check in `validate` and add the listen check**

In `Config.validate`, replace the existing first stanza:

```go
	if c.Socket == "" {
		return fmt.Errorf("%w: socket path is empty", sandbox.ErrInvalid)
	}
```

with:

```go
	// The socket may be omitted only when a network listener replaces it.
	// Neither one set is a daemon that starts, binds nothing and answers
	// nothing — indistinguishable from a working one until a caller times out.
	if c.Socket == "" && c.Listen == nil {
		return fmt.Errorf("%w: neither socket nor listen is set; the daemon would accept nothing", sandbox.ErrInvalid)
	}
	if c.Listen != nil {
		if err := c.Listen.validate(); err != nil {
			return err
		}
	}
```

Add the method below `Config.validate`:

```go
// validate refuses a listen block that is not completely specified.
//
// Nothing here defaults. A daemon that starts listening on a network interface
// because a key was omitted is the failure this block exists to avoid, and a
// listener that accepted any certificate its CA ever signed would make the CA
// the entire access control list.
func (l *ListenConfig) validate() error {
	if l.Address == "" {
		return fmt.Errorf("%w: listen.address is empty; a bind address has no default", sandbox.ErrInvalid)
	}
	if _, _, err := net.SplitHostPort(l.Address); err != nil {
		return fmt.Errorf("%w: listen.address %q is not host:port: %s", sandbox.ErrInvalid, l.Address, err)
	}
	switch {
	case l.TLS.CertFile == "":
		return fmt.Errorf("%w: listen.tls.cert_file is empty", sandbox.ErrInvalid)
	case l.TLS.KeyFile == "":
		return fmt.Errorf("%w: listen.tls.key_file is empty", sandbox.ErrInvalid)
	case l.TLS.ClientCAFile == "":
		return fmt.Errorf("%w: listen.tls.client_ca_file is empty; without it any client certificate would be accepted", sandbox.ErrInvalid)
	case len(l.TLS.AllowedClientCNs) == 0:
		return fmt.Errorf("%w: listen.tls.allowed_client_cns is empty; the CA alone must not be the access control list", sandbox.ErrInvalid)
	}
	return nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/daemon/ -run 'TestLoadAcceptsListen|TestLoadRejects|TestIsWildcardHost' -v`
Expected: PASS, all subtests.

- [ ] **Step 6: Run the whole daemon package to check nothing regressed**

Run: `go test ./internal/daemon/`
Expected: PASS. `TestLoadRejectsEmptySocket` (or equivalently named existing test) may now fail because an empty socket is no longer refused on its own — if so, update it to also omit `listen`, which is the case that is still a refusal.

- [ ] **Step 7: Document the block in the reference config**

Append to `deploy/openbloxd.example.yaml`, after the `reap_interval` line:

```yaml
# A network listener, so the daemon can run on a host of its own. OPTIONAL and
# off by default: omit this block entirely and the daemon serves only the Unix
# socket above, which stays the recommended arrangement wherever the caller and
# the daemon share a host.
#
# Nothing here has a default. A daemon that started listening on a network
# interface because a key was omitted is the failure this block exists to
# avoid, so every field below is required once `listen` is present.
#listen:
#  address: "127.0.0.1:9443"
#  tls:
#    cert_file: /etc/openbloxd/tls/server.crt
#    key_file: /etc/openbloxd/tls/server.key
#    # The CA that signs callers. It must sign NOTHING else: with certificate
#    # verification alone, this CA is the entire access control list.
#    client_ca_file: /etc/openbloxd/tls/clients-ca.crt
#    # The second gate, and the reason a CA mis-issuance is survivable. Only a
#    # certificate whose Common Name is listed here is accepted. Revoking a
#    # caller means removing its name and restarting: there is no CRL or OCSP.
#    allowed_client_cns: ["sandbox-caller"]
```

- [ ] **Step 8: Commit**

```bash
git add internal/daemon/config.go internal/daemon/config_test.go deploy/openbloxd.example.yaml
git commit -m "feat(daemon): accept a listen block, refusing every incomplete form

Nothing in the block defaults, and allowed_client_cns is mandatory: with
certificate verification alone the CA would be the entire access control
list. The socket becomes optional only when listen replaces it."
```

---

### Task 2: `ListenTLS` — the network listener and its two gates

**Files:**
- Create: `internal/testpki/testpki.go`
- Create: `internal/daemon/listener_tls.go`
- Create: `internal/daemon/listener_tls_test.go`

**Interfaces:**
- Consumes: `ListenConfig` and `TLSConfig` from Task 1.
- Produces: `func ListenTLS(cfg ListenConfig) (net.Listener, error)`, used by Task 4. Also produces the shared helper package `internal/testpki` with `testpki.New() (*PKI, error)`, fields `PKI.CAFile / CertFile / KeyFile string`, `(*PKI).ClientTLS(cn string) (*tls.Config, error)`, and `(*PKI).Pool() *x509.CertPool` — used by Tasks 5 and 7.

Two constraints shape this helper, and both are easy to trip over:

- **It must not import `internal/daemon`.** The daemon's tests are `package daemon` (not `daemon_test`), so a helper that imported `daemon` to return a `ListenConfig` would be an import cycle. `testpki` therefore deals only in file paths, and each test assembles its own `ListenConfig`.
- **It must not import `testing`.** It is a normal package, not a `_test.go` file, so importing `testing` would register test flags into anything that links it. It returns errors and the callers do `if err != nil { t.Fatal(err) }`.

- [ ] **Step 1: Write the shared test PKI package**

Create `internal/testpki/testpki.go`. It lives in `internal/`, so it is reachable from both `internal/daemon` and `pkg/brokerclient` without becoming public API:

```go
// Package testpki generates a throwaway certificate authority for tests that
// need a real mTLS handshake.
//
// It is a normal package rather than a _test.go file because two packages
// need it, and it deliberately imports neither testing nor internal/daemon —
// the former would leak test flags into anything linking it, the latter would
// be an import cycle with the daemon's in-package tests.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PKI is a certificate authority plus a server keypair signed by it, written
// to a temporary directory. A test needing a second, untrusted authority just
// calls New again.
type PKI struct {
	Dir      string
	CAFile   string
	CertFile string
	KeyFile  string

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// New returns a PKI whose files are written under dir. Pass t.TempDir().
func New(dir string) (*PKI, error) {
	caCert, caKey, err := issueCA()
	if err != nil {
		return nil, err
	}
	p := &PKI{
		Dir:      dir,
		CAFile:   filepath.Join(dir, "ca.crt"),
		CertFile: filepath.Join(dir, "server.crt"),
		KeyFile:  filepath.Join(dir, "server.key"),
		caCert:   caCert,
		caKey:    caKey,
	}
	if err := writePEM(p.CAFile, "CERTIFICATE", caCert.Raw); err != nil {
		return nil, err
	}

	der, key, err := p.issue("openbloxd", true)
	if err != nil {
		return nil, err
	}
	if err := writePEM(p.CertFile, "CERTIFICATE", der); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(p.KeyFile, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}
	return p, nil
}

// Pool is this authority's certificate, for verifying the server leg.
func (p *PKI) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	return pool
}

// ClientTLS returns a client config presenting a certificate with the given
// Common Name and trusting this authority.
func (p *PKI) ClientTLS(cn string) (*tls.Config, error) {
	der, key, err := p.issue(cn, false)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		RootCAs:      p.Pool(),
		ServerName:   "openbloxd",
	}, nil
}

// WriteClient writes a client keypair for cn and returns its cert and key
// paths, for a caller configured by file rather than by tls.Config.
func (p *PKI) WriteClient(cn string) (certFile, keyFile string, err error) {
	der, key, err := p.issue(cn, false)
	if err != nil {
		return "", "", err
	}
	certFile = filepath.Join(p.Dir, cn+".crt")
	keyFile = filepath.Join(p.Dir, cn+".key")
	if err := writePEM(certFile, "CERTIFICATE", der); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// ServerTLS is the daemon-side config a test listener needs: this authority's
// keypair, requiring and verifying a client certificate from it.
func (p *PKI) ServerTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.Pool(),
	}, nil
}

func (p *PKI) issue(cn string, server bool) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"openbloxd", "localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func issueCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "testpki-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func writePEM(path, blockType string, der []byte) error {
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
```

- [ ] **Step 2: Write the failing listener tests**

Create `internal/daemon/listener_tls_test.go`:

```go
package daemon

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/internal/testpki"
)

// newPKI builds a throwaway authority in the test's own temp directory.
func newPKI(t *testing.T) *testpki.PKI {
	t.Helper()
	p, err := testpki.New(t.TempDir())
	if err != nil {
		t.Fatalf("testpki.New: %v", err)
	}
	return p
}

// listenConfigFor assembles a complete ListenConfig pointing at a PKI. It
// lives here rather than in testpki because testpki must not import this
// package — the tests are `package daemon`, so that would be a cycle.
func listenConfigFor(p *testpki.PKI, addr string, cns ...string) ListenConfig {
	return ListenConfig{
		Address: addr,
		TLS: TLSConfig{
			CertFile:         p.CertFile,
			KeyFile:          p.KeyFile,
			ClientCAFile:     p.CAFile,
			AllowedClientCNs: cns,
		},
	}
}

// clientTLS is ClientTLS with the error folded into the test.
func clientTLS(t *testing.T, p *testpki.PKI, cn string) *tls.Config {
	t.Helper()
	cfg, err := p.ClientTLS(cn)
	if err != nil {
		t.Fatalf("ClientTLS(%q): %v", cn, err)
	}
	return cfg
}

// serveOnce accepts on ln and answers every request with 200 "ok", so a test
// can assert whether a client got through the handshake at all.
func serveOnce(t *testing.T, ln net.Listener) {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// get dials addr with the given client config and returns the response body,
// or the error. The request matters: under TLS 1.3 the server verifies the
// client certificate in its own flight, so a rejected client often completes
// Handshake() successfully and only sees the alert on its first read. Testing
// the handshake alone would pass against a listener that accepts everyone.
func get(t *testing.T, addr string, cfg *tls.Config) (string, error) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	defer c.CloseIdleConnections()
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestListenTLSAcceptsAnAllowedCommonName(t *testing.T) {
	pki := newPKI(t)
	ln, err := ListenTLS(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	defer func() { _ = ln.Close() }()
	serveOnce(t, ln)

	got, err := get(t, ln.Addr().String(), clientTLS(t, pki, "sandbox-caller"))
	if err != nil {
		t.Fatalf("allowed client was rejected: %v", err)
	}
	if got != "ok" {
		t.Errorf("body = %q, want ok", got)
	}
}

// The gate that would vanish if the CN allowlist were ever dropped as
// redundant: this certificate is signed by the configured CA and verifies
// perfectly. Only the allowlist stops it.
func TestListenTLSRejectsUnlistedCommonName(t *testing.T) {
	pki := newPKI(t)
	ln, err := ListenTLS(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	defer func() { _ = ln.Close() }()
	serveOnce(t, ln)

	if _, err := get(t, ln.Addr().String(), clientTLS(t, pki, "someone-else")); err == nil {
		t.Fatal("a certificate with an unlisted common name was accepted")
	}
}

func TestListenTLSRejectsForeignCA(t *testing.T) {
	pki := newPKI(t)
	foreign := newPKI(t)
	ln, err := ListenTLS(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	defer func() { _ = ln.Close() }()
	serveOnce(t, ln)

	// Right name, wrong CA. Trust our real CA for the server leg so the only
	// thing under test is the client certificate.
	cfg := clientTLS(t, foreign, "sandbox-caller")
	cfg.RootCAs = pki.Pool()
	if _, err := get(t, ln.Addr().String(), cfg); err == nil {
		t.Fatal("a certificate from an unconfigured CA was accepted")
	}
}

func TestListenTLSRejectsNoClientCertificate(t *testing.T) {
	pki := newPKI(t)
	ln, err := ListenTLS(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	defer func() { _ = ln.Close() }()
	serveOnce(t, ln)

	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pki.Pool(), ServerName: "openbloxd"}
	if _, err := get(t, ln.Addr().String(), cfg); err == nil {
		t.Fatal("a client presenting no certificate was accepted")
	}
}

func TestListenTLSRefusesUnreadableCA(t *testing.T) {
	pki := newPKI(t)
	cfg := listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller")
	cfg.TLS.ClientCAFile = pki.Dir + "/absent.crt"
	if _, err := ListenTLS(cfg); err == nil {
		t.Fatal("ListenTLS succeeded with an unreadable client CA")
	} else if !strings.Contains(err.Error(), "client CA") {
		t.Errorf("error = %v, want it to name the client CA", err)
	}
}
```

`pki.Pool()` used by the last two tests is already provided by `internal/testpki` from Step 1; nothing further is needed.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/daemon/ -run TestListenTLS -v`
Expected: FAIL — compile error, `ListenTLS` undefined.

- [ ] **Step 4: Implement `ListenTLS`**

Create `internal/daemon/listener_tls.go`:

```go
package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// ListenTLS creates the network listener the daemon serves on.
//
// Two gates, both during the handshake. The client certificate must chain to
// the configured CA, and its Common Name must be on the allowlist.
//
// The second gate is not belt-and-braces. With verification alone the CA is
// the whole access control list, so a CA shared with anything else silently
// grants sandbox creation to whatever that other thing issued. The allowlist
// is what makes a CA mis-issuance survivable, and what makes the set of
// permitted callers something an operator can read in one place.
//
// Rejecting during the handshake rather than in a middleware means a caller
// that fails either gate never reaches the request router at all.
func ListenTLS(cfg ListenConfig) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.TLS.ClientCAFile) //nolint:gosec // the operator's own config path, not request input
	if err != nil {
		return nil, fmt.Errorf("read client CA %q: %w", cfg.TLS.ClientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: client CA %q contains no certificate", sandbox.ErrInvalid, cfg.TLS.ClientCAFile)
	}

	allowed := make(map[string]struct{}, len(cfg.TLS.AllowedClientCNs))
	for _, cn := range cfg.TLS.AllowedClientCNs {
		allowed[cn] = struct{}{}
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			// RequireAndVerifyClientCert has already built and verified a
			// chain by the time this runs, so chains[0][0] is the leaf.
			cn := chains[0][0].Subject.CommonName
			if _, ok := allowed[cn]; !ok {
				// Logged because the client only sees a TLS alert, and an
				// operator debugging a rejected caller has nothing else to
				// go on.
				slog.Warn("rejected client certificate: common name is not allowed",
					slog.String("common_name", cn))
				return fmt.Errorf("client certificate common name %q is not allowed", cn)
			}
			return nil
		},
	}

	ln, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", cfg.Address, err)
	}
	return tls.NewListener(ln, tlsCfg), nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/daemon/ -run TestListenTLS -v`
Expected: PASS, all five.

- [ ] **Step 6: Commit**

```bash
git add internal/testpki/testpki.go internal/daemon/listener_tls.go internal/daemon/listener_tls_test.go
git commit -m "feat(daemon): add a TLS listener gated on CA and common name

Both gates run in the handshake, so a caller failing either never reaches
the router. The common-name allowlist is the gate that keeps a CA
mis-issuance survivable, and it is asserted by a test using a certificate
that verifies perfectly against the configured CA."
```

---

### Task 3: `Caller` — identity on every request

**Files:**
- Create: `internal/daemon/caller.go`
- Create: `internal/daemon/caller_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `daemon.Caller{Transport, Name string}`, `daemon.WithCaller(http.Handler) http.Handler`, `daemon.CallerFrom(context.Context) (Caller, bool)`, and the constants `TransportUnix` / `TransportTLS`. Task 4 wraps the handler with `WithCaller`; Task 5 relies on `WithCaller` being transparent.

- [ ] **Step 1: Write the failing tests**

Create `internal/daemon/caller_test.go`:

```go
package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCallerRecordsUnixCaller(t *testing.T) {
	var got Caller
	var ok bool
	h := WithCaller(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = CallerFrom(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/profiles", nil))

	if !ok {
		t.Fatal("no caller on the context")
	}
	if got.Transport != TransportUnix {
		t.Errorf("Transport = %q, want %q", got.Transport, TransportUnix)
	}
	// SO_PEERCRED is unimplemented, so a local caller has no name yet. This
	// asserts the current honest answer rather than a placeholder.
	if got.Name != "" {
		t.Errorf("Name = %q, want empty for a unix caller", got.Name)
	}
}

func TestWithCallerRecordsCertificateCommonName(t *testing.T) {
	var got Caller
	h := WithCaller(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = CallerFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/profiles", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "sandbox-caller"}},
	}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.Transport != TransportTLS {
		t.Errorf("Transport = %q, want %q", got.Transport, TransportTLS)
	}
	if got.Name != "sandbox-caller" {
		t.Errorf("Name = %q, want sandbox-caller", got.Name)
	}
}

func TestCallerFromReportsAbsence(t *testing.T) {
	if _, ok := CallerFrom(context.Background()); ok {
		t.Fatal("CallerFrom reported a caller on a bare context")
	}
}
```

Add `"context"` to that file's imports.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/daemon/ -run 'TestWithCaller|TestCallerFrom' -v`
Expected: FAIL — compile error, `WithCaller` undefined.

- [ ] **Step 3: Implement it**

Create `internal/daemon/caller.go`:

```go
package daemon

import (
	"context"
	"log/slog"
	"net/http"
)

// Transport names the way a request arrived.
const (
	TransportUnix = "unix"
	TransportTLS  = "tls"
)

// Caller is who made a request.
//
// Nothing consumes this yet. It exists anyway because a transport that
// discards the caller's identity has to be reopened to add per-caller quotas
// or an audit trail, and the place to record identity is where it is still
// available.
//
// Transport is carried explicitly rather than inferred from an empty Name: a
// log line for a security boundary should say whether a request arrived
// locally or over a network, not leave it to be deduced.
type Caller struct {
	Transport string
	Name      string
}

type callerKey struct{}

// WithCaller records the caller on the request context, over every transport.
//
// Name is empty for a Unix caller because SO_PEERCRED is unimplemented; that
// is the local transport's identity seam and is unrelated to this one.
func WithCaller(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := Caller{Transport: TransportUnix}
		if r.TLS != nil {
			c.Transport = TransportTLS
			if len(r.TLS.PeerCertificates) > 0 {
				c.Name = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			// Logged only for network callers. The Unix socket is the
			// high-volume local path and its behaviour is deliberately
			// unchanged; a remote request is the one worth an audit line.
			slog.Info("openbloxd request",
				slog.String("caller", c.Name),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path))
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}

// CallerFrom returns the caller recorded by WithCaller.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/daemon/ -run 'TestWithCaller|TestCallerFrom' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/caller.go internal/daemon/caller_test.go
git commit -m "feat(daemon): record the caller on every request context

Nothing consumes it yet. A transport that discards who called has to be
reopened to add per-caller quotas, so the identity is recorded where it is
still available. Remote requests also get an audit log line; the unix path
is unchanged."
```

---

### Task 4: Serve both listeners from one handler

**Files:**
- Modify: `cmd/openbloxd/main.go`

**Interfaces:**
- Consumes: `Config.Listen`, `ListenConfig.IsWildcardHost` (Task 1), `ListenTLS` (Task 2), `WithCaller` (Task 3).
- Produces: nothing other tasks consume.

- [ ] **Step 1: Build the listener set in `run`**

In `cmd/openbloxd/main.go`, replace:

```go
	ln, err := daemon.Listen(cfg.Socket, cfg.SocketGroup)
	if err != nil {
		return err
	}
```

with:

```go
	// One handler, two listeners. There is no second route table that could
	// drift from the first, which is what makes "policy is unreachable
	// regardless of transport" a property of the design rather than a rule
	// somebody has to remember.
	var lns []net.Listener
	if cfg.Socket != "" {
		ln, err := daemon.Listen(cfg.Socket, cfg.SocketGroup)
		if err != nil {
			return err
		}
		lns = append(lns, ln)
	}
	if cfg.Listen != nil {
		if cfg.Listen.IsWildcardHost() {
			// Legitimate for a daemon whose network namespace is already the
			// boundary, and a serious mistake otherwise. The difference is
			// invisible in the config file, so say it out loud at boot.
			slog.Warn("listen.address binds every interface; the daemon is reachable from any network this host is on",
				slog.String("address", cfg.Listen.Address))
		}
		ln, err := daemon.ListenTLS(*cfg.Listen)
		if err != nil {
			return err
		}
		lns = append(lns, ln)
	}
```

- [ ] **Step 2: Wrap the handler and update the boot log**

Replace the `httpSrv` construction and the `slog.Info` line below it:

```go
	httpSrv := &http.Server{Handler: daemon.WithCaller(srv.Handler()), ReadHeaderTimeout: 10 * time.Second}

	network := "off"
	if cfg.Listen != nil {
		network = cfg.Listen.Address
	}
	slog.Info("openbloxd listening",
		slog.String("socket", cfg.Socket),
		slog.String("network", network),
		slog.Int("profiles", len(cfg.Profiles)))
	return serve(ctx, httpSrv, lns...)
```

- [ ] **Step 3: Make `serve` variadic over listeners**

Replace the `serve` function's signature and its goroutine, and fix the drain:

```go
func serve(ctx context.Context, httpSrv *http.Server, lns ...net.Listener) error {
	serveErr := make(chan error, len(lns))
	for _, ln := range lns {
		go func() { serveErr <- httpSrv.Serve(ln) }()
	}

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("openbloxd: graceful shutdown did not complete in time", slog.Any("error", err))
	}

	// Shutdown closes every listener, so each Serve returns. Drain them all:
	// leaving one undrained would leak its goroutine, and returning on the
	// first would hide a real failure behind another listener's ErrServerClosed.
	var firstErr error
	for range lns {
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) && firstErr == nil {
			firstErr = fmt.Errorf("serve: %w", err)
		}
	}
	return firstErr
}
```

- [ ] **Step 4: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: no output. If `net` is reported unused or missing, adjust the import block in `main.go` — it is already imported for the old `serve` signature.

- [ ] **Step 5: Verify a socket-only config still boots unchanged**

Run:

```bash
go run ./cmd/openbloxd --config deploy/openbloxd.example.yaml 2>&1 | head -5
```

Expected: it fails on the Docker connection or the `CHANGEME` image digest, **not** on config validation, and any log line it prints reports `network=off`. This confirms an existing deployment is untouched.

- [ ] **Step 6: Commit**

```bash
git add cmd/openbloxd/main.go
git commit -m "feat(daemon): serve the unix socket and the TLS listener together

Both feed one http.Server with one handler, so no route table can drift
between transports. A wildcard bind is warned about at boot, since the
difference between deliberate and careless is invisible in the config."
```

---

### Task 5: Policy stays unreachable over both transports

**Files:**
- Modify: `internal/daemon/policy_test.go`

**Interfaces:**
- Consumes: `newTestServer` (existing, `sandboxes_test.go`), and from Task 2's `listener_tls_test.go`: `newPKI`, `listenConfigFor`, `clientTLS`. Also `ListenTLS` (Task 2) and `WithCaller` (Task 3).
- Produces: nothing.

This is the requirement the spec insists must be a test rather than a convention: nothing about a remote caller may relax what a profile pins.

Those helpers are all in `package daemon` already, so nothing needs importing to reach them — only the stdlib addition below.

- [ ] **Step 1: Add a transport harness to `policy_test.go`**

Add `"io"` to `internal/daemon/policy_test.go`'s imports. (`net/http`, `net/http/httptest`, `strings`, `testing` and the `sandbox` package are already there.) Then add:

```go
// postSandboxes sends body to POST /sandboxes and returns the status code.
// The two implementations are the whole point: one goes straight to the
// handler, the other crosses a real authenticated TLS connection.
type transport struct {
	name string
	post func(t *testing.T, srv *Server, body string) int
}

func transports() []transport {
	return []transport{
		{
			name: "direct",
			post: func(t *testing.T, srv *Server, body string) int {
				t.Helper()
				rec := httptest.NewRecorder()
				WithCaller(srv.Handler()).ServeHTTP(rec,
					httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body)))
				return rec.Code
			},
		},
		{
			name: "tls",
			post: func(t *testing.T, srv *Server, body string) int {
				t.Helper()
				pki := newPKI(t)
				ln, err := ListenTLS(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
				if err != nil {
					t.Fatalf("ListenTLS: %v", err)
				}
				httpSrv := &http.Server{Handler: WithCaller(srv.Handler())}
				go func() { _ = httpSrv.Serve(ln) }()
				t.Cleanup(func() { _ = httpSrv.Close() })

				c := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS(t, pki, "sandbox-caller")}}
				defer c.CloseIdleConnections()
				resp, err := c.Post("https://"+ln.Addr().String()+"/sandboxes",
					"application/json", strings.NewReader(body))
				if err != nil {
					t.Fatalf("post over tls: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				_, _ = io.Copy(io.Discard, resp.Body)
				return resp.StatusCode
			},
		},
	}
}
```

`io` is used to drain the response body; everything else the harness needs is already imported or already in the package.

- [ ] **Step 2: Run the existing table over both transports**

Replace the body of `TestNoRequestFieldReachesTheSpec`'s loop. Keep the `bodies` slice exactly as it is, and change the loop to:

```go
	for _, tr := range transports() {
		for _, body := range bodies {
			t.Run(tr.name+"/"+body, func(t *testing.T) {
				srv := newTestServer(t)
				fake := srv.backend.(*fakeBackend)

				code := tr.post(t, srv, body)
				if code < 400 || code > 499 {
					t.Fatalf("status = %d, want 4xx", code)
				}
				// The assertion that matters: a handler can reject a request
				// and still have called Create first. Nothing from the body
				// may have reached the backend, over either transport.
				if len(fake.created) != 0 {
					t.Fatalf("a rejected request created a sandbox: %+v", fake.created)
				}
			})
		}
	}
```

- [ ] **Step 3: Assert an accepted remote request gets exactly the profile's policy**

Add a new test to the same file:

```go
// The mirror of TestNoRequestFieldReachesTheSpec: a request that IS accepted
// over the network must land on the profile's policy and nothing else. A
// transport that quietly widened a Spec would pass the rejection table above
// while still being broken.
func TestRemoteAcceptedRequestGetsExactlyTheProfilePolicy(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)

	pki := newPKI(t)
	ln, err := ListenTLS(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	httpSrv := &http.Server{Handler: WithCaller(srv.Handler())}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS(t, pki, "sandbox-caller")}}
	defer c.CloseIdleConnections()
	resp, err := c.Post("https://"+ln.Addr().String()+"/sandboxes", "application/json",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	if err != nil {
		t.Fatalf("post over tls: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	got := fake.created["a"]
	want := sandbox.NewSpec(srv.cfg.Profiles["code-exec"].Options()...)
	if got.Runtime != want.Runtime || got.Egress != want.Egress ||
		got.User != want.User || got.Resources != want.Resources || got.Image != want.Image {
		t.Errorf("spec = %+v, want the profile's %+v", got, want)
	}
}
```

- [ ] **Step 4: Run the policy tests**

Run: `go test ./internal/daemon/ -run 'TestNoRequestFieldReachesTheSpec|TestRemoteAccepted' -v`
Expected: PASS. Every body in the table now runs twice, once per transport — confirm both `direct/` and `tls/` subtests appear in the output.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/policy_test.go
git commit -m "test(daemon): assert policy is unreachable over the network too

Every body in the hostile-field table now runs over a real authenticated
TLS connection as well as against the handler directly, and an accepted
remote request is asserted to land on exactly the profile's policy."
```

---

### Task 6: `brokerclient.NewRemote`

**Files:**
- Modify: `pkg/brokerclient/client.go`
- Create: `pkg/brokerclient/remote.go`
- Create: `pkg/brokerclient/remote_test.go`

**Interfaces:**
- Consumes: nothing from Tasks 1–5 (this is the client half; it talks to a daemon over the wire).
- Produces: `brokerclient.TLSFiles{CertFile, KeyFile, CAFile, ServerName string}` and `func NewRemote(address string, files TLSFiles, opts ...Option) (*Client, error)`. Also produces the internal `Client.dial` field that Task 7 consumes.

- [ ] **Step 1: Write the failing tests**

Create `pkg/brokerclient/remote_test.go`:

```go
package brokerclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func TestNewRemoteRequiresAnAddress(t *testing.T) {
	_, err := NewRemote("", TLSFiles{CertFile: "/c", KeyFile: "/k", CAFile: "/ca"})
	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

// The credential is not optional and cannot be defaulted away: a client that
// presented nothing would be talking to a daemon that must reject it, and the
// clearer failure is here.
func TestNewRemoteRequiresEveryCredentialFile(t *testing.T) {
	cases := map[string]TLSFiles{
		"no cert": {KeyFile: "/k", CAFile: "/ca"},
		"no key":  {CertFile: "/c", CAFile: "/ca"},
		"no ca":   {CertFile: "/c", KeyFile: "/k"},
		"none":    {},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewRemote("127.0.0.1:9443", files)
			if !errors.Is(err, sandbox.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNewRemoteReportsAnUnreadableCredential(t *testing.T) {
	_, err := NewRemote("127.0.0.1:9443", TLSFiles{
		CertFile: "/nonexistent/c", KeyFile: "/nonexistent/k", CAFile: "/nonexistent/ca",
	})
	if err == nil {
		t.Fatal("NewRemote succeeded with unreadable credential files")
	}
	if !strings.Contains(err.Error(), "keypair") {
		t.Errorf("error = %v, want it to name the keypair", err)
	}
}

// New keeps its exact signature and behaviour: a same-host caller is untouched
// by any of this.
func TestNewStillTakesOnlyASocketPath(t *testing.T) {
	c, err := New("/run/openbloxd/openbloxd.sock")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.target != "/run/openbloxd/openbloxd.sock" {
		t.Errorf("target = %q, want the socket path", c.target)
	}
	if c.dial == nil {
		t.Error("dial is nil; New must install a dialler")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./pkg/brokerclient/ -run 'TestNewRemote|TestNewStill' -v`
Expected: FAIL — compile error, `TLSFiles` and `NewRemote` undefined.

- [ ] **Step 3: Refactor `Client` onto a single dial seam**

In `pkg/brokerclient/client.go`, replace the `socket` field and the `New` constructor:

```go
type Client struct {
	http *http.Client

	// target is the socket path or the network address, for error messages.
	target string

	// dial opens one connection to the daemon. It is the only place either
	// transport is chosen, so the pooled HTTP client and DialPort's raw
	// stream cannot diverge on which one they use.
	dial func(ctx context.Context) (net.Conn, error)

	signer         *preview.Signer
	previewBase    string
	previewHandler *preview.Handler
}

// New returns a Client that dials openbloxd at socketPath.
func New(socketPath string, opts ...Option) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("%w: socket path is empty", sandbox.ErrInvalid)
	}
	return newClient(socketPath, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}, opts...)
}

// newClient wires a dialler into a Client and applies its options.
func newClient(target string, dial func(context.Context) (net.Conn, error), opts ...Option) (*Client, error) {
	c := &Client{target: target, dial: dial}
	c.http = &http.Client{
		Transport: &http.Transport{
			// The address net/http computed is discarded: there is exactly
			// one place this client ever talks to, and c.dial knows it.
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return c.dial(ctx)
			},
		},
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}
```

Also update the `baseURL` comment above it, which currently says "dialled straight to socketPath":

```go
// baseURL is a placeholder: every request is dialled by c.dial regardless of
// what host or scheme the URL names. It exists only because net/http requires
// a well-formed URL to build a request from.
const baseURL = "http://openbloxd"
```

- [ ] **Step 4: Implement `NewRemote`**

Create `pkg/brokerclient/remote.go`:

```go
package brokerclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// TLSFiles is the client's half of the mTLS credential openbloxd verifies.
//
// It takes file paths rather than a *tls.Config deliberately. Exposing a
// *tls.Config would mean accepting InsecureSkipVerify and then refusing it at
// runtime; taking paths makes an unverified client inexpressible instead. If
// in-memory certificates are ever needed, that is an Option.
type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string

	// ServerName overrides the name verified against the daemon's
	// certificate. Leave it empty and it is derived from the dial address,
	// which is what you want unless you dial by IP and the certificate names
	// a host.
	ServerName string
}

// NewRemote returns a Client that dials openbloxd over the network.
//
// The credential is a positional argument rather than an Option because it is
// not optional: openbloxd requires a client certificate, and a Client built
// without one could only ever fail at the handshake.
func NewRemote(address string, files TLSFiles, opts ...Option) (*Client, error) {
	if address == "" {
		return nil, fmt.Errorf("%w: address is empty", sandbox.ErrInvalid)
	}
	cfg, err := files.config()
	if err != nil {
		return nil, err
	}
	return newClient(address, func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{Config: cfg}
		return d.DialContext(ctx, "tcp", address)
	}, opts...)
}

func (f TLSFiles) config() (*tls.Config, error) {
	if f.CertFile == "" || f.KeyFile == "" || f.CAFile == "" {
		return nil, fmt.Errorf("%w: cert, key and CA files are all required to reach openbloxd over a network", sandbox.ErrInvalid)
	}
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	caPEM, err := os.ReadFile(f.CAFile) //nolint:gosec // the caller's own configured path, not request input
	if err != nil {
		return nil, fmt.Errorf("read CA %q: %w", f.CAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: CA %q contains no certificate", sandbox.ErrInvalid, f.CAFile)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   f.ServerName,
	}, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./pkg/brokerclient/ -run 'TestNewRemote|TestNewStill' -v`
Expected: PASS.

- [ ] **Step 6: Run the whole client package**

Run: `go test ./pkg/brokerclient/`
Expected: PASS. Any existing test referencing `c.socket` must be updated to `c.target`.

- [ ] **Step 7: Commit**

```bash
git add pkg/brokerclient/client.go pkg/brokerclient/remote.go pkg/brokerclient/remote_test.go
git commit -m "feat(brokerclient): add NewRemote for reaching openbloxd over TLS

The credential takes file paths rather than a *tls.Config, so an
unverified client is inexpressible rather than refused at runtime. New
keeps its exact signature; both constructors now share one dial seam."
```

---

### Task 7: `DialPort` over the network

**Files:**
- Modify: `pkg/brokerclient/dial.go`
- Modify: `pkg/brokerclient/dial_test.go`
- Modify: `pkg/brokerclient/remote_test.go` (adds the two helpers below)

**Interfaces:**
- Consumes: `Client.dial`, `TLSFiles` and `NewRemote` (Task 6); `internal/testpki` (Task 2).
- Produces: nothing.

- [ ] **Step 1: Point `DialPort` at the shared dial seam**

In `pkg/brokerclient/dial.go`, replace:

```go
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, fmt.Errorf("dial openbloxd: %w", err)
	}
```

with:

```go
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial openbloxd: %w", err)
	}
```

Remove `"net"` from the imports if it is now unused — `net.Conn` is still in the signature, so it will remain needed.

- [ ] **Step 2: Write the failing test for the hijack over TLS**

Add to `pkg/brokerclient/dial_test.go`:

```go
// CloseWrite is reached through a type assertion on net.Conn, so a change of
// transport can break it silently: net/http asserts for it on request bodies,
// and without it a proxied request carrying a body never completes. *tls.Conn
// has the method, and this pins that.
func TestDialPortOverTLSSupportsCloseWrite(t *testing.T) {
	pki, files := newPKI(t)
	ln := listen(t, pki)
	t.Cleanup(func() { _ = ln.Close() })

	// A daemon stub that answers the upgrade and then echoes.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Connection: Upgrade\r\nUpgrade: "+brokerapi.UpgradeProto+"\r\n\r\n")
		_, _ = io.Copy(conn, br)
	}()

	c, err := NewRemote(ln.Addr().String(), files)
	if err != nil {
		t.Fatalf("NewRemote: %v", err)
	}
	conn, err := c.DialPort(context.Background(), "a", 8080)
	if err != nil {
		t.Fatalf("DialPort: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the dialled connection does not support CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("echo = %q, want ping", got)
	}
}
```

This uses the same `internal/testpki` package Task 2 created — no certificate-generation code is duplicated. Add these two helpers to `pkg/brokerclient/remote_test.go`:

```go
// newPKI builds a throwaway authority plus a client keypair on disk, and
// returns the TLSFiles a Client is constructed from.
func newPKI(t *testing.T) (*testpki.PKI, TLSFiles) {
	t.Helper()
	p, err := testpki.New(t.TempDir())
	if err != nil {
		t.Fatalf("testpki.New: %v", err)
	}
	certFile, keyFile, err := p.WriteClient("sandbox-caller")
	if err != nil {
		t.Fatalf("WriteClient: %v", err)
	}
	return p, TLSFiles{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   p.CAFile,
		// The daemon's certificate names "openbloxd", but the test dials
		// 127.0.0.1 — so the name to verify has to be given explicitly. This
		// is exactly the case ServerName exists for.
		ServerName: "openbloxd",
	}
}

// listen starts a TLS listener that requires a client certificate from p.
func listen(t *testing.T, p *testpki.PKI) net.Listener {
	t.Helper()
	cfg, err := p.ServerTLS()
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return tls.NewListener(ln, cfg)
}
```

Imports for `remote_test.go` gain `"crypto/tls"`, `"net"`, and `"github.com/blox-eng/openblox/internal/testpki"`. `dial_test.go` gains `"bufio"`, `"context"`, `"io"`, `"net/http"` and `"github.com/blox-eng/openblox/pkg/brokerapi"` if they are not already present.

`pkg/brokerclient` is a public package importing `internal/testpki`, which is allowed — `internal/` restricts who may import it, not who it may be imported *by* within the same module — and it happens only from `_test.go` files, so nothing about the shipped package surface changes.

- [ ] **Step 3: Run the test to verify it fails, then passes**

Run: `go test ./pkg/brokerclient/ -run TestDialPortOverTLS -v`
Expected: first FAIL (helpers undefined), then PASS once Step 2's helpers are written.

- [ ] **Step 4: Run both packages in full**

Run: `go test ./internal/daemon/ ./pkg/brokerclient/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/brokerclient/dial.go pkg/brokerclient/dial_test.go pkg/brokerclient/remote_test.go
git commit -m "feat(brokerclient): dial sandbox ports over the network transport

DialPort now goes through the same dial seam as the pooled client, so the
two cannot diverge. CloseWrite is reached by type assertion and a
transport change breaks it silently, so *tls.Conn's is pinned by test."
```

---

### Task 8: Document the remote threat model

**Files:**
- Modify: `docs/security.md`

**Interfaces:**
- Consumes: the configuration shape from Task 1.
- Produces: nothing.

- [ ] **Step 1: Add the section**

Append to `docs/security.md`. Read the file first and match its existing heading level and voice.

````markdown
## Remote transport

openbloxd serves a Unix socket by default, and that remains the recommended
arrangement wherever the caller and the daemon share a host. The optional
`listen` block adds a network listener so the daemon can run on a machine of
its own — because gVisor contains escape, not contention, and sandboxes
otherwise compete for CPU, memory bandwidth and disk IO with whatever runs
beside them.

A network listener requires mutual TLS. There is no unauthenticated network
mode and there is no way to configure one.

### What authenticates a caller

Two gates, both during the handshake:

1. The client certificate must chain to `client_ca_file`.
2. Its Common Name must appear in `allowed_client_cns`.

The second is not redundant. With verification alone **the CA is the entire
access control list** — any certificate it ever signs is accepted. Use a CA
that signs nothing else, and treat the allowlist as the thing that makes a
mis-issuance survivable.

### What this does not protect against

**mTLS authenticates the process holding the key, not its intent.** A caller
that has been compromised is a *valid* caller: it holds the certificate.
Authentication contributes nothing to that case.

That case is the one openbloxd exists for, and the credential is not what
answers it. The guarantee is that a compromised caller gains sandboxes rather
than the host, and it is enforced by the profile being unreachable from a
request. Nothing about arriving over a network relaxes that, and it is
asserted by test over both transports rather than left as a convention.

**A private network is a real mitigation and a poor sole control.** Running
the daemon on a VPN or a private subnet meaningfully reduces exposure and is
recommended. It is not a substitute for the credential: it authenticates a
route rather than a peer, and it fails open the moment anything else on that
network is compromised.

**Confidentiality in transit is TLS's alone.** Exec output, file reads and
dialled streams all cross the network now, with no application-layer
encryption beneath.

### Revocation

There is none beyond configuration. Go checks neither CRL nor OCSP by default,
and openbloxd runs neither.

**To revoke a caller: remove its Common Name from `allowed_client_cns` and
restart the daemon.** `RuntimeDirectoryPreserve=yes` in the shipped unit makes
a restart transparent to clients that mount the socket directory.

This is a limitation, not a design feature. It is workable for a small,
enumerated set of callers and would not be workable at a scale where
certificates are issued automatically — anything issuing certificates
automatically should revoke them automatically too.

### Issuing the certificates

openbloxd is not a certificate authority and does not want to be. A minimal
private CA, sufficient for one daemon and one caller:

```bash
# A CA that signs nothing else.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj "/CN=openbloxd-ca"

# The daemon's certificate. The SAN must match the address callers dial.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=openbloxd"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out server.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth")

# One caller. The CN is what goes in allowed_client_cns.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout client.key -out client.csr -subj "/CN=sandbox-caller"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out client.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth")
```

Keep `ca.key` off both machines once the certificates are issued.
````

- [ ] **Step 2: Verify the docs build**

Run: `mkdocs build --strict` (or `make docs` if defined; check the `Makefile` and `mkdocs.yml` first).
Expected: no warnings about the new section.

- [ ] **Step 3: Commit**

```bash
git add docs/security.md
git commit -m "docs(security): state the remote threat model and its limits

Says plainly that a compromised caller is a valid caller and that the
profile, not the credential, is what bounds it; that a private network is
not a sole control; and that revocation is a restart."
```

---

### Task 9: Full verification before the PR

**Files:** none.

This task exists because pushing is expensive and a second push to fix a lint error is a wasted release chain.

- [ ] **Step 1: Run everything**

Run: `make all`
Expected: `vet`, `lint` and `test` all pass with no findings.

- [ ] **Step 2: Run the integration tests**

Run: `make test-integration`
Expected: PASS, or skip cleanly if Docker is unavailable. Read the output — a silent skip of every test is not a pass.

- [ ] **Step 3: Confirm no new dependency crept in**

Run: `go mod tidy && git diff --exit-code go.mod go.sum`
Expected: no diff. This work is stdlib-only.

- [ ] **Step 4: Audit the diff for anything deployment-specific**

Run: `git diff origin/main -- . | grep -inE '[0-9]{1,3}(\.[0-9]{1,3}){3}'`
Expected: only `127.0.0.1` (and a documented `0.0.0.0` example). Also manually scan the diff against your own organisation's internal service names, deployment names, hostnames, and VPN/overlay-network products — none belong in this public repository. Anything found is a leak of deployment-specific detail and must be replaced with a neutral placeholder.

- [ ] **Step 5: Open the PR**

```bash
git push -u origin feat/32-remote-transport
gh pr create --repo blox-eng/openblox \
  --title "feat(daemon): remote transport with mTLS caller authentication" \
  --body "Closes #32. Design: specs/2026-08-18-openbloxd-remote-transport-design.md"
```

The title must begin `feat(` — the release is derived from the squashed commit, and any other type produces no release at all.

---

## Post-merge

The release runs itself: CI green on `main` triggers `release.yml`, which tags
and publishes; `publish-daemon.yml` and `publish-image.yml` hang off that tag.

- [ ] Read the tag that was actually created — do not assume it.
- [ ] Confirm `openbloxd-linux-amd64` and `openbloxd-linux-amd64.sha256` are attached to the release. If they are missing, re-run `publish-daemon.yml` via `workflow_dispatch` against the existing tag rather than re-tagging.
