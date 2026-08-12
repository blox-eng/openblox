package preview

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDialer stands in for a sandbox: it serves HTTP over an in-memory pipe and
// records what it was asked to reach.
type fakeDialer struct {
	handler http.Handler

	mu    sync.Mutex
	calls []string
	fail  error
}

func (d *fakeDialer) DialPort(_ context.Context, name string, port int) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, fmt.Sprintf("%s:%d", name, port))
	failure := d.fail
	d.mu.Unlock()

	if failure != nil {
		return nil, failure
	}

	client, server := net.Pipe()
	go http.Serve(newSingleConnListener(server), d.handler) //nolint:errcheck // the listener yields one conn then closes
	return client, nil
}

func (d *fakeDialer) reached() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

// singleConnListener serves exactly the one connection it was built around.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() {})
	close(l.done)
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		fmt.Fprintf(w, "path=%s auth=%q body=%s", r.URL.Path, r.Header.Get("Authorization"), body)
	})
}

func readAll(r *http.Request) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.String(), err
}

func newTestHandler(t *testing.T, d *fakeDialer) (*Handler, *Signer) {
	t.Helper()
	s := testSigner(t)
	return NewHandler(d, s), s
}

func request(t *testing.T, h *Handler, path, token string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestProxyForwardsAnAuthenticatedRequest(t *testing.T) {
	d := &fakeDialer{handler: echoHandler()}
	h, s := newTestHandler(t, d)

	token, err := s.Sign("session-a", 3000, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	resp := request(t, h, URL("", "session-a", 3000)+"a/b?q=1", token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	if !strings.Contains(body.String(), "path=/a/b") {
		t.Errorf("sandbox saw %q; the route prefix was not stripped", body.String())
	}
	if got := d.reached(); len(got) != 1 || got[0] != "session-a:3000" {
		t.Errorf("dialled %v, want [session-a:3000]", got)
	}
}

// The credential authorises the hop to the sandbox. Code inside the sandbox must
// never see it, or it holds a key to its own front door.
func TestProxyStripsTheCredentialBeforeForwarding(t *testing.T) {
	d := &fakeDialer{handler: echoHandler()}
	h, s := newTestHandler(t, d)

	token, err := s.Sign("session-a", 3000, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	resp := request(t, h, URL("", "session-a", 3000), token)
	defer resp.Body.Close()

	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	if !strings.Contains(body.String(), `auth=""`) {
		t.Errorf("the sandbox received the Authorization header: %q", body.String())
	}
	if strings.Contains(body.String(), token) {
		t.Error("the token reached the sandbox")
	}
}

func TestProxyRefusesUnauthenticatedRequests(t *testing.T) {
	d := &fakeDialer{handler: echoHandler()}
	h, s := newTestHandler(t, d)

	valid, err := s.Sign("session-a", 3000, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	expired, err := s.Sign("session-a", 3000, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	tests := map[string]struct{ path, token string }{
		"no token":         {URL("", "session-a", 3000), ""},
		"garbage token":    {URL("", "session-a", 3000), "nonsense"},
		"expired token":    {URL("", "session-a", 3000), expired},
		"wrong sandbox":    {URL("", "session-b", 3000), valid},
		"wrong port":       {URL("", "session-a", 3001), valid},
		"no bearer at all": {URL("", "session-a", 3000), ""},
	}
	for name, tc := range tests {
		resp := request(t, h, tc.path, tc.token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, resp.StatusCode)
		}
	}
	if got := d.reached(); len(got) != 0 {
		t.Errorf("an unauthenticated request reached a sandbox: %v", got)
	}
}

// A credential in the query string ends up in access logs, browser history, and
// the Referer of every link the page follows. It must not be accepted there.
func TestProxyIgnoresACredentialInTheQueryString(t *testing.T) {
	d := &fakeDialer{handler: echoHandler()}
	h, s := newTestHandler(t, d)

	token, err := s.Sign("session-a", 3000, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	for _, param := range []string{"token", "auth", "access_token", "apikey"} {
		resp := request(t, h, URL("", "session-a", 3000)+"?"+param+"="+token, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("?%s= was accepted as a credential (status %d)", param, resp.StatusCode)
		}
	}
}

func TestProxyRejectsMalformedRoutes(t *testing.T) {
	d := &fakeDialer{handler: echoHandler()}
	h, _ := newTestHandler(t, d)

	for _, path := range []string{
		"/", "/preview/", "/preview/session-a", "/preview/session-a/notaport/",
		"/preview/session-a/0/", "/preview/session-a/65536/", "/preview//3000/",
		"/elsewhere/session-a/3000/",
	} {
		resp := request(t, h, path, "irrelevant")
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestRevokedTokenIsRefused(t *testing.T) {
	d := &fakeDialer{handler: echoHandler()}
	h, s := newTestHandler(t, d)

	token, err := s.Sign("session-a", 3000, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	resp := request(t, h, URL("", "session-a", 3000), token)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status before revoke = %d, want 200", resp.StatusCode)
	}

	h.Revoke(token)

	resp = request(t, h, URL("", "session-a", 3000), token)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status after revoke = %d, want 401", resp.StatusCode)
	}
}

// Revoking one credential must not take down another issued for the same port.
func TestRevokeAffectsOnlyItsOwnToken(t *testing.T) {
	d := &fakeDialer{handler: echoHandler()}
	h, s := newTestHandler(t, d)
	expiry := time.Now().Add(time.Hour)

	doomed, err := s.Sign("session-a", 3000, expiry)
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	survivor, err := s.Sign("session-a", 3000, expiry)
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	h.Revoke(doomed)

	resp := request(t, h, URL("", "session-a", 3000), survivor)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the surviving token was refused: status %d", resp.StatusCode)
	}
}

// An unreachable sandbox is a bad gateway, and the reason stays on this side of
// the wire rather than describing the host to whoever holds the token.
func TestProxyReportsAnUnreachableSandboxWithoutDetail(t *testing.T) {
	d := &fakeDialer{handler: echoHandler(), fail: fmt.Errorf("dial /var/run/docker.sock: permission denied")}
	h, s := newTestHandler(t, d)

	token, err := s.Sign("session-a", 3000, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	resp := request(t, h, URL("", "session-a", 3000), token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	if strings.Contains(body.String(), "docker.sock") {
		t.Errorf("the response leaked host detail: %q", body.String())
	}
}

func TestURLEscapesTheSandboxName(t *testing.T) {
	got := URL("https://example.test/", "tenant/acme user", 3000)
	want := "https://example.test/preview/tenant%2Facme%20user/3000/"
	if got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}
