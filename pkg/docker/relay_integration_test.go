//go:build integration

package docker

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// The relay has to work on images that have nc and no python, and on images that
// have python and no nc. Both halves are exercised by hiding one tool from the
// script's lookup and checking the other still carries a request.
func TestRelayWorksWithoutNc(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-relay-python")

	if !hasCommand(t, sb, "python3") {
		t.Skip("test image has no python3; the fallback cannot be exercised here")
	}
	serveInSandbox(t, sb, "<h1>python relay</h1>")

	// The nc branch is pointed at a path that does not exist, so the script must
	// fall through to the Python one. python3 is then invoked by absolute path so
	// the substitution cannot accidentally be what makes it work.
	python := commandPath(t, sb, "python3")
	body := getThroughRelay(t, b, "openblox-test-relay-python",
		strings.NewReplacer("exec nc 127.0.0.1", "exec /nonexistent/nc 127.0.0.1",
			"exec python3 -c", "exec "+python+" -c").Replace(relayScript))

	if !strings.Contains(body, "python relay") {
		t.Errorf("body = %q, want the page served inside the sandbox", body)
	}
}

// An image with neither tool must fail loudly at dial rather than hang or return
// an empty body that looks like a broken server.
func TestRelayReportsAnImageWithNoForwarder(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-relay-none")

	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c",
			strings.NewReplacer("command -v nc", "command -v definitely-not-nc",
				"command -v python3", "command -v definitely-not-python3").Replace(relayScript),
			"openblox", "8080"},
	})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if res.ExitCode != 127 {
		t.Errorf("exit = %d, want 127 when no forwarder exists", res.ExitCode)
	}
	if !strings.Contains(string(res.Stderr), "neither nc nor python3") {
		t.Errorf("stderr = %q, want it to name the missing tools", res.Stderr)
	}
}

func hasCommand(t *testing.T, sb sandbox.Sandbox, name string) bool {
	t.Helper()
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c", "command -v " + name},
	})
	return err == nil && res.ExitCode == 0
}

func commandPath(t *testing.T, sb sandbox.Sandbox, name string) string {
	t.Helper()
	res, err := sb.Exec(context.Background(), sandbox.Command{
		Argv: []string{"sh", "-c", "command -v " + name},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("command -v %s = %v (exit %d)", name, err, res.ExitCode)
	}
	return strings.TrimSpace(string(res.Stdout))
}

// getThroughRelay dials the sandbox with an overridden relay script and performs
// one HTTP request over the resulting connection.
func getThroughRelay(t *testing.T, b *Backend, name, script string) string {
	t.Helper()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			sb, err := b.Open(ctx, name)
			if err != nil {
				return nil, err
			}
			return sb.(*dockerSandbox).dialPortWith(ctx, previewPort, script)
		},
	}}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://sandbox.invalid/", nil)
	if err != nil {
		t.Fatalf("NewRequest = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through the relay = %v", err)
	}
	defer resp.Body.Close()

	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	return body.String()
}
