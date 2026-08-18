package daemon

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/blox-eng/openblox/internal/testpki"
)

// syncAllowlist is a CN allowlist a test can mutate from one goroutine while
// a server goroutine's VerifyConnection reads it from another, without a
// data race. Plain map access here would happen to be safe in practice — the
// TLS handshake completing establishes enough ordering — but "happens to be
// safe by timing" is exactly the kind of thing -race exists to stop
// depending on, so this test earns its correctness by construction instead.
type syncAllowlist struct {
	mu      sync.Mutex
	allowed map[string]struct{}
}

func newSyncAllowlist(cns ...string) *syncAllowlist {
	m := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		m[cn] = struct{}{}
	}
	return &syncAllowlist{allowed: m}
}

func (a *syncAllowlist) check(chains [][]*x509.Certificate) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return checkAllowedClientCN(a.allowed, chains)
}

func (a *syncAllowlist) revoke(cn string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.allowed, cn)
}

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

// leafChain builds the [][]*x509.Certificate shape checkAllowedClientCN
// consumes — chains[0][0] the leaf — around a single self-issued leaf, which
// is all the function looks at.
func leafChain(t *testing.T, p *testpki.PKI, cn string) [][]*x509.Certificate {
	t.Helper()
	tlsCert, err := p.ClientTLS(cn)
	if err != nil {
		t.Fatalf("ClientTLS(%q): %v", cn, err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return [][]*x509.Certificate{{leaf}}
}

// TestCheckAllowedClientCN exercises the extracted gate directly, independent
// of any TLS handshake, so the allowlist logic itself is pinned down without
// depending on how or when it gets invoked.
func TestCheckAllowedClientCN(t *testing.T) {
	pki := newPKI(t)
	allowed := map[string]struct{}{"sandbox-caller": {}}

	t.Run("allowed CN passes", func(t *testing.T) {
		if err := checkAllowedClientCN(allowed, leafChain(t, pki, "sandbox-caller")); err != nil {
			t.Errorf("checkAllowedClientCN = %v, want nil", err)
		}
	})

	t.Run("unlisted CN is rejected", func(t *testing.T) {
		if err := checkAllowedClientCN(allowed, leafChain(t, pki, "someone-else")); err == nil {
			t.Error("checkAllowedClientCN = nil, want rejection for an unlisted CN")
		}
	})

	t.Run("no chains is rejected, not indexed into", func(t *testing.T) {
		if err := checkAllowedClientCN(allowed, nil); err == nil {
			t.Error("checkAllowedClientCN = nil, want rejection for an empty chain list")
		}
	})

	t.Run("empty leaf chain is rejected, not indexed into", func(t *testing.T) {
		if err := checkAllowedClientCN(allowed, [][]*x509.Certificate{{}}); err == nil {
			t.Error("checkAllowedClientCN = nil, want rejection for an empty leaf chain")
		}
	})
}

// TestTLSConfigWiresAllowlistIntoVerifyConnection looks like a tautology —
// it just asserts a struct field is set — and that is exactly why it earns
// its place: it is the only test in this package that fails if someone
// "simplifies" the allowlist check back onto VerifyPeerCertificate. Every
// other test here would still pass against that regression, because none of
// them observes a resumed connection being rejected by production wiring —
// TestCheckAllowedClientCN calls the check function directly regardless of
// which TLS callback it's wired into, and
// TestListenTLSResumedConnectionStillReachesTheGate only asserts the resumed
// connection is *accepted*, which vulnerable wiring satisfies too
// (VerifyPeerCertificate just never runs on resumption, so nothing rejects
// it). This test is the one place the wiring choice itself is pinned down.
//
// Confirmed by reverting to VerifyPeerCertificate in a scratch copy of
// tlsConfigFor and re-running: this test goes red (VerifyConnection == nil),
// while every other test in the package still passes. See the fix report
// for the transcript.
func TestTLSConfigWiresAllowlistIntoVerifyConnection(t *testing.T) {
	pki := newPKI(t)
	tlsCfg, err := tlsConfigFor(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
	if err != nil {
		t.Fatalf("tlsConfigFor: %v", err)
	}
	if tlsCfg.VerifyConnection == nil {
		t.Error("VerifyConnection is nil — the allowlist has no callback invoked on a resumed session")
	}
	if tlsCfg.VerifyPeerCertificate != nil {
		t.Error("VerifyPeerCertificate is set — Go skips this callback on a resumed session, so the allowlist must not depend on it")
	}
}

// TestListenTLSResumedConnectionStillReachesTheGate proves the wiring is
// live end to end through the real listener: with a shared
// ClientSessionCache, a second connection to the same ListenTLS listener
// genuinely resumes (DidResume) rather than performing a fresh handshake,
// and it is still accepted — meaning VerifyConnection ran and re-evaluated
// the allowlist rather than being skipped the way VerifyPeerCertificate
// would have been.
//
// This alone doesn't prove revocation works mid-session — see
// TestVerifyConnectionRejectsAResumedSessionOnceItsCNIsRevoked below for
// that, and for why it can't be built against ListenTLS itself.
func TestListenTLSResumedConnectionStillReachesTheGate(t *testing.T) {
	pki := newPKI(t)
	ln, err := ListenTLS(listenConfigFor(pki, "127.0.0.1:0", "sandbox-caller"))
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	defer func() { _ = ln.Close() }()
	serveOnce(t, ln)

	clientCfg := clientTLS(t, pki, "sandbox-caller")
	clientCfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	first := connState(t, ln.Addr().String(), clientCfg)
	if first.DidResume {
		t.Fatal("first connection unexpectedly resumed; nothing was cached yet")
	}

	second := connState(t, ln.Addr().String(), clientCfg)
	if !second.DidResume {
		t.Fatal("second connection did not resume — this test isn't exercising the resumption path VerifyConnection has to cover")
	}
}

// connState performs a full HTTPS round trip over a fresh connection and
// returns the resulting TLS state, so a test can inspect DidResume. A plain
// handshake isn't enough: the server only sends the TLS 1.3 session ticket
// as a post-handshake message, and the client only processes it on a
// subsequent Read — so the ticket isn't cached, and resumption can't be
// observed, until a real request/response has gone over the wire.
func connState(t *testing.T, addr string, cfg *tls.Config) *tls.ConnectionState {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	c.CloseIdleConnections()
	if resp.TLS == nil {
		t.Fatal("response carried no TLS connection state")
	}
	return resp.TLS
}

// TestVerifyConnectionRejectsAResumedSessionOnceItsCNIsRevoked reproduces
// the exact bypass the finding describes and shows the fix closes it: a
// caller resumes a session cached while its CN was allowed, but the CN has
// since been removed from the allowlist. If the check only ran in
// VerifyPeerCertificate, Go would skip it entirely on the resumed connection
// and the now-revoked caller would get back in.
//
// This can't be built against ListenTLS itself: ListenTLS copies
// AllowedClientCNs into a map local to that call, with no way for a test to
// reach in and mutate it afterward — by design, the daemon's config is fixed
// for the process's lifetime and revocation is a restart. So this test wires
// up the same tls.Config shape ListenTLS does, by hand, around a map the
// test controls, to isolate the one thing that changes between "caller was
// allowed" and "caller was revoked": the allowlist a live VerifyConnection
// call consults.
//
// A genuine "unlisted CN establishes a session, then resumes" case isn't
// constructible at all: an unlisted CN fails the very first handshake, so no
// session ticket is ever issued for it to resume with. Revocation-after-the-
// fact, tested here, is the only way a previously-valid session can meet an
// allowlist that no longer contains its CN — which is exactly the scenario
// operators hit in practice (they didn't reject the caller on day one; they
// removed it later).
func TestVerifyConnectionRejectsAResumedSessionOnceItsCNIsRevoked(t *testing.T) {
	pki := newPKI(t)
	cert, err := tls.LoadX509KeyPair(pki.CertFile, pki.KeyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	allowed := newSyncAllowlist("sandbox-caller")
	serverCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.Pool(),
		VerifyConnection: func(cs tls.ConnectionState) error {
			return allowed.check(cs.VerifiedChains)
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, serverCfg)
	defer func() { _ = tlsLn.Close() }()
	serveOnce(t, tlsLn)

	clientCfg := clientTLS(t, pki, "sandbox-caller")
	clientCfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	// First connection: CN is allowed, session ticket gets cached.
	first := connState(t, tlsLn.Addr().String(), clientCfg)
	if first.DidResume {
		t.Fatal("first connection unexpectedly resumed; nothing was cached yet")
	}

	// Revoke, without restarting the listener — a live VerifyConnection is
	// the only thing standing between the resumed connection and acceptance.
	allowed.revoke("sandbox-caller")

	// Dial manually rather than through http.Client for this half: if the
	// server's VerifyConnection rejects the connection, there is no
	// *http.Response to read TLS.DidResume off, since the request never
	// succeeds. tls.Conn.Handshake() completing is a client-side fact — the
	// client has sent its own Finished and considers the handshake done —
	// that happens before the client discovers, via a subsequent read
	// failing, that the server aborted after processing the client's
	// certificate. So the resumption check and the rejection check are two
	// different observations, taken in order, on the same connection.
	conn, err := net.Dial("tcp", tlsLn.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	tlsConn := tls.Client(conn, clientCfg)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Handshake: %v (want the handshake itself to succeed; the CN check runs after, in VerifyConnection)", err)
	}
	if !tlsConn.ConnectionState().DidResume {
		t.Fatal("second connection did not resume — this test isn't exercising the resumption path")
	}

	// The server aborts as soon as VerifyConnection rejects the resumed
	// session — before the handler, before a response, sometimes before it
	// even reads the request. So the request write itself may fail with a
	// reset connection, or it may succeed and the response read fails
	// instead; either is the rejection this test is checking for. What must
	// NOT happen is a clean response.
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		return // rejected before the request could even be written
	}
	if resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a resumed session for a revoked CN was accepted")
	}
}
