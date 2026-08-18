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
