package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// TestNoRequestFieldReachesTheSpec attacks handleCreate with bodies that name
// every field a hostile caller might hope weakens isolation. Asserting a 4xx
// is the weaker half of each case — a handler can reject a request and still
// have called Create first. The assertion that matters is fake.created: it
// must stay empty, proving nothing from the body ever reached the backend.
//
// The obvious policy-field names are the floor. Beyond them: casing variants of a field
// name (decode is case-insensitive on known fields, so an unknown field must
// stay unknown regardless of case), a body that is syntactically valid JSON
// but not an object, and duplicate JSON keys — encoding/json takes the last
// occurrence of a repeated key, so a case that would pass validation on its
// first value must still be judged on the value that actually wins.
func TestNoRequestFieldReachesTheSpec(t *testing.T) {
	bodies := []string{
		`{"name":"a","profile":"code-exec","runtime":"runc"}`,
		`{"name":"a","profile":"code-exec","egress":"unrestricted"}`,
		`{"name":"a","profile":"code-exec","privileged":true}`,
		`{"name":"a","profile":"code-exec","binds":["/:/host"]}`,
		`{"name":"a","profile":"code-exec","pid_mode":"host"}`,
		`{"name":"a","profile":"code-exec","user":"0:0"}`,
		`{"name":"a","profile":"code-exec","cpus":64}`,
		`{"name":"a","profile":"code-exec","memory_mb":1048576}`,
		`{"name":"a","profile":"code-exec","image":"evil.example.com/x"}`,
		`{"name":"a","profile":"code-exec","registry_auth":{"username":"x"}}`,
		`{"name":"a","profile":"code-exec","max_processes":0}`,

		// Casing variant of a field that does not exist on CreateRequest at
		// all: this is not a distinct attack from the lowercase "runtime"
		// case above (same rejection, same code path), just a pin on
		// encoding/json's case-insensitive matching — the same mechanism that
		// lets a caller write "Profile" for the real "profile" field must not
		// also resolve "Runtime" to some field that isn't there.
		`{"name":"a","profile":"code-exec","Runtime":"runc"}`,

		// Valid JSON, but not an object: decoding into CreateRequest must
		// fail before any field of it is ever inspected.
		`[1,2,3]`,
		`"code-exec"`,
		`null`,

		// Duplicate "profile" key: json.Decoder keeps the last occurrence.
		// The value actually used for policy resolution must be the one
		// validated — an attacker naming a real profile first and a bogus
		// one second must not slip through on the first value.
		`{"name":"a","profile":"code-exec","profile":"no-such-profile"}`,

		// Duplicate "labels" key where the first occurrence is benign and
		// the second smuggles the reserved profile-marker label. The whole
		// field is replaced by the last occurrence, not merged, so the
		// reserved-label check must see (and reject) the winning value. This
		// is also the only case in this file that carries the strong half of
		// the reserved-label guarantee (fake.created empty, not just 4xx) —
		// TestCreateRejectsReservedProfileLabel in sandboxes_test.go now
		// carries that assertion too, so the two do not depend on each other.
		`{"name":"a","profile":"code-exec","labels":{"x":"1"},"labels":{"openbloxd.profile":"pwned"}}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			srv := newTestServer(t)
			fake := srv.backend.(*fakeBackend)

			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(body)))

			if rec.Code < 400 || rec.Code > 499 {
				t.Fatalf("status = %d, want 4xx, body %s", rec.Code, rec.Body.String())
			}
			if len(fake.created) != 0 {
				t.Fatalf("a rejected request created a sandbox: %+v", fake.created)
			}
		})
	}
}

func TestAcceptedRequestGetsExactlyTheProfilePolicy(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec","env":["K=v"],"labels":{"t":"1"}}`)))

	// Without this, a 400 and a wrong-policy 201 both surface as the same
	// zero-value Spec mismatch below — the failure wouldn't say which.
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
	}

	got := fake.created["a"]
	want := sandbox.NewSpec(srv.cfg.Profiles["code-exec"].Options()...)
	if got.Runtime != want.Runtime || got.Egress != want.Egress ||
		got.User != want.User || got.Resources != want.Resources || got.Image != want.Image {
		t.Errorf("spec = %+v, want the profile's %+v", got, want)
	}
}

// TestHostileLabelValuesDoNotReachTypedSpecFields is the accepted-request
// counterpart to TestNoRequestFieldReachesTheSpec: a label is caller data by
// design (opaque string in, opaque string out), so labels.runtime = "runc" is
// not itself refused. What matters is that a value that merely LOOKS like a
// policy field, sitting inside a legitimately caller-settable map, still
// never reaches the typed Spec fields it names.
func TestHostileLabelValuesDoNotReachTypedSpecFields(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec","labels":{"runtime":"runc","egress":"unrestricted","privileged":"true","user":"0:0"}}`)))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
	}

	got := fake.created["a"]
	want := sandbox.NewSpec(srv.cfg.Profiles["code-exec"].Options()...)
	if got.Runtime != want.Runtime || got.Egress != want.Egress || got.User != want.User {
		t.Errorf("spec = %+v, want the profile's %+v — a label value leaked into a typed field", got, want)
	}
	if got.Labels["runtime"] != "runc" {
		t.Errorf("labels = %+v, want the caller's runtime=runc preserved as an opaque label", got.Labels)
	}
}

// A reserved-profile-label test is not duplicated here:
// TestCreateRejectsReservedProfileLabel in sandboxes_test.go covers the same
// body and asserts both the 400 and fake.created being empty — the full
// guarantee, under the name that claims it. A second copy would only invite
// the two to drift apart.
