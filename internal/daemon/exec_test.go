package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExecPassesArgvAndTimeout(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/a/exec",
		strings.NewReader(`{"argv":["echo","hi"],"env":["FOO=bar"],"dir":"/work","timeout":"5s"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	cmd := fake.lastCommand
	if got := cmd.Argv; len(got) != 2 || got[0] != "echo" || got[1] != "hi" {
		t.Errorf("argv = %v, want [echo hi]", got)
	}
	if cmd.Env == nil || len(cmd.Env) != 1 || cmd.Env[0] != "FOO=bar" {
		t.Errorf("env = %v, want [FOO=bar]", cmd.Env)
	}
	if cmd.Dir != "/work" {
		t.Errorf("dir = %q, want /work", cmd.Dir)
	}
	if cmd.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", cmd.Timeout)
	}
}

func TestExecRejectsBadTimeoutString(t *testing.T) {
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/a/exec",
		strings.NewReader(`{"argv":["echo"],"timeout":"soon"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// The leading slash of an absolute path is percent-encoded on the wire (see
// brokerclient.filesRoute) so it survives the "{path...}" wildcard instead of
// colliding with net/http's own doubled-slash redirect. "%2Fworkspace" is
// therefore what a well-behaved client actually sends for "/workspace".
func TestWriteFileStreamsBodyToSandbox(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sandboxes/a/files/%2Fworkspace/main.go",
		strings.NewReader("package main"))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body)
	}
	if fake.written["/workspace/main.go"] != "package main" {
		t.Errorf("written = %q", fake.written["/workspace/main.go"])
	}
}

// The daemon must not depend on a well-behaved client to enforce this: a
// caller speaking the wire protocol directly, without going through
// brokerclient, must not be able to reach a path the library would refuse
// either — see pkg/docker/sandbox.go's identical path.IsAbs check. Before
// this test existed, a request like this reached sb.WriteFile with "/" blindly
// prepended, turning an unencoded (relative-looking) wildcard segment into a
// different absolute path instead of being refused.
func TestWriteFileRejectsANonAbsoluteWirePath(t *testing.T) {
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sandboxes/a/files/workspace/main.go",
		strings.NewReader("package main"))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
}
