package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/brokerapi"
)

// errStub is a plain error with no sentinel wrapping, standing in for an
// unrecognised failure a backend might return.
type errStub string

func (e errStub) Error() string { return string(e) }

// These two tests exercise decode and fail directly through a throwaway mux,
// not through Server.Handler(): both are generic properties of the two
// helpers themselves, shared by every handler that calls them, so testing
// them against a route-specific handler would tie a package-wide contract to
// one route's business logic. TestUnknownFieldOnCreateIsRejected in
// sandboxes_test.go re-asserts the same property through the real
// POST /sandboxes route, once a route exists to assert it against.

func TestUnknownFieldIsRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /test/decode", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := decode[brokerapi.CreateRequest](w, r); !ok {
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test/decode",
		strings.NewReader(`{"name":"a","profile":"code-exec","runtime":"runc"}`))
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body brokerapi.Error
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != brokerapi.KindInvalid {
		t.Errorf("kind = %q, want %q", body.Kind, brokerapi.KindInvalid)
	}
	if !strings.Contains(body.Message, "runtime") {
		t.Errorf("message %q should name the offending field", body.Message)
	}
}

func TestInternalErrorDetailIsNotReturned(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /test/fail", func(w http.ResponseWriter, _ *http.Request) {
		fail(w, errStub("secret host path /var/lib/docker"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test/fail", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/var/lib/docker") {
		t.Error("internal detail leaked into the response body")
	}
}
