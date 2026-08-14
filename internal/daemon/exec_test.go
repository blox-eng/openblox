package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExecPassesArgvAndClampedTimeout(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/a/exec",
		strings.NewReader(`{"argv":["echo","hi"],"timeout":"5s"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if got := fake.lastCommand.Argv; len(got) != 2 || got[0] != "echo" {
		t.Errorf("argv = %v", got)
	}
	if fake.lastCommand.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", fake.lastCommand.Timeout)
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

func TestWriteFileStreamsBodyToSandbox(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sandboxes/a/files/workspace/main.go",
		strings.NewReader("package main"))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body)
	}
	if fake.written["/workspace/main.go"] != "package main" {
		t.Errorf("written = %q", fake.written["/workspace/main.go"])
	}
}
