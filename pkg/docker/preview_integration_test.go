//go:build integration

// pkg/brokerclient/broker_integration_test.go re-runs the preview assertions
// here through openbloxd's DialPort instead of talking to Docker directly.
// That suite is hand-mirrored, not shared code — keep the two in step
// deliberately, since nothing else will notice drift.
package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

const previewPort = 8080

func previewKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, preview.MinKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key = %v", err)
	}
	return key
}

// serveInSandbox stands up an HTTP server on the sandbox's loopback interface
// and returns once it is answering.
//
// It is built out of nc rather than a real server because alpine's busybox does
// not ship the httpd applet, and the point here is the transport, not the
// server. Each connection is answered once and closed, which Content-Length and
// Connection: close make a complete HTTP/1.1 exchange.
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

// The sandbox's only interface is loopback, which nothing outside it can reach,
// so this proves the connection is riding the runtime's exec channel rather than
// any kind of route.
func TestDialPortReachesALoopbackServerWithNoNetwork(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-dial")
	ctx := context.Background()

	serveInSandbox(t, sb, "<h1>from inside</h1>")

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return b.DialPort(ctx, "openblox-test-dial", previewPort)
		},
	}}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sandbox.invalid/index.html", nil)
	if err != nil {
		t.Fatalf("NewRequest = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through the exec channel = %v", err)
	}
	defer resp.Body.Close()

	var got bytes.Buffer
	_, _ = got.ReadFrom(resp.Body)
	if !strings.Contains(got.String(), "from inside") {
		t.Errorf("body = %q, want the page served inside the sandbox", got.String())
	}
}

// End to end: Expose mints a credential, the handler validates it, and the
// traffic reaches a port that has no route to it.
func TestPreviewServesAnExposedPort(t *testing.T) {
	b, err := New(WithPreviews(previewKey(t), "https://previews.test"))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	name := "openblox-test-preview"
	sb := create(t, b, name)
	ctx := context.Background()

	serveInSandbox(t, sb, "<h1>previewed</h1>")

	p, err := sb.Expose(ctx, previewPort, time.Minute)
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

	srv := httptest.NewServer(b.PreviewHandler())
	defer srv.Close()

	body, status := get(t, srv.URL+preview.RoutePrefix+"/"+name+"/8080/index.html", p.Token)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", status, body)
	}
	if !strings.Contains(body, "previewed") {
		t.Errorf("body = %q, want the page served inside the sandbox", body)
	}

	// And without the credential, nothing.
	_, status = get(t, srv.URL+preview.RoutePrefix+"/"+name+"/8080/index.html", "")
	if status != http.StatusUnauthorized {
		t.Errorf("status without a token = %d, want 401", status)
	}

	// Revoke closes it before expiry.
	if err := sb.Revoke(ctx, previewPort, p.Token); err != nil {
		t.Fatalf("Revoke = %v", err)
	}
	_, status = get(t, srv.URL+preview.RoutePrefix+"/"+name+"/8080/index.html", p.Token)
	if status != http.StatusUnauthorized {
		t.Errorf("status after revoke = %d, want 401", status)
	}
}

// A backend with no preview configuration must say so rather than hand back a
// URL that nothing serves.
func TestExposeWithoutConfigurationFails(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-preview-unconfigured")

	if _, err := sb.Expose(context.Background(), previewPort, time.Minute); err == nil {
		t.Error("Expose succeeded on a backend with no preview configuration")
	}
}

func get(t *testing.T, url, token string) (body string, status int) {
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
