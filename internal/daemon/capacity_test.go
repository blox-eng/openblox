package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/brokerapi"
)

// newCappedServer builds a server whose code-exec profile admits at most limit
// concurrent sandboxes, with `existing` already live under the named profiles.
func newCappedServer(t *testing.T, limit int, existing map[string]string) *Server {
	t.Helper()
	cfg := &Config{
		Socket: "/tmp/unused.sock",
		Profiles: map[string]Profile{
			"code-exec": {Image: "example.com/i@sha256:abc", Runtime: "runsc", MaxSandboxes: limit},
			"browser":   {Image: "example.com/b@sha256:def"},
		},
	}
	return New(&fakeBackend{existing: existing}, cfg)
}

func createSandbox(srv *Server, name, profile string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(fmt.Sprintf(`{"name":%q,"profile":%q}`, name, profile)))
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestLoadRejectsNegativeMaxSandboxes(t *testing.T) {
	path := writeConfig(t, `
socket: /tmp/s.sock
profiles:
  p:
    image: example.com/i@sha256:abc
    max_sandboxes: -1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error: a negative cap reads as 'unlimited' but is an operator typo")
	}
	if !strings.Contains(err.Error(), "max_sandboxes") {
		t.Errorf("error %q should name the offending field", err)
	}
}

func TestCreateRefusesWhenProfileIsAtCapacity(t *testing.T) {
	srv := newCappedServer(t, 2, map[string]string{"a": "code-exec", "b": "code-exec"})

	rec := createSandbox(srv, "c", "code-exec")

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429, body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != brokerapi.KindAtCapacity {
		t.Errorf("kind = %q, want %q — a caller must tell 'try later' from 'malformed'",
			body.Kind, brokerapi.KindAtCapacity)
	}
}

func TestCreateAtCapacityStillServesAnExistingSandbox(t *testing.T) {
	srv := newCappedServer(t, 2, map[string]string{"a": "code-exec", "b": "code-exec"})

	// "a" is already counted against the cap, so reusing it consumes no new
	// slot. Refusing here would break warm reuse exactly when the host is busy.
	rec := createSandbox(srv, "a", "code-exec")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
	}
}

func TestCreateCapacityCountsOnlyTheRequestedProfile(t *testing.T) {
	srv := newCappedServer(t, 2, map[string]string{"x": "browser", "y": "browser"})

	rec := createSandbox(srv, "a", "code-exec")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 — browser sandboxes must not consume code-exec capacity, body %s",
			rec.Code, rec.Body.String())
	}
}

func TestCreateIsUnlimitedWhenMaxSandboxesIsUnset(t *testing.T) {
	srv := newCappedServer(t, 0, map[string]string{"a": "code-exec", "b": "code-exec", "c": "code-exec"})

	rec := createSandbox(srv, "d", "code-exec")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 — unset max_sandboxes means unlimited, body %s",
			rec.Code, rec.Body.String())
	}
}

// TestConcurrentCreatesCannotExceedCapacity is the point of the feature: a
// retry storm arrives in parallel, and counting live sandboxes without holding
// a reservation would let every request pass the check before any of them had
// created anything.
func TestConcurrentCreatesCannotExceedCapacity(t *testing.T) {
	srv := newCappedServer(t, 1, nil)
	fake := srv.backend.(*fakeBackend)

	start := make(chan struct{})
	fake.createBlock = start

	const callers = 8
	codes := make(chan int, callers)
	for i := range callers {
		go func() { codes <- createSandbox(srv, fmt.Sprintf("s%d", i), "code-exec").Code }()
	}
	close(start)

	var created, refused int
	for range callers {
		switch code := <-codes; code {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Errorf("unexpected status %d", code)
		}
	}
	if created != 1 {
		t.Errorf("created = %d, want 1 — the cap must hold under concurrent creates", created)
	}
	if refused != callers-1 {
		t.Errorf("refused = %d, want %d", refused, callers-1)
	}
}
