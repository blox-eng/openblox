package daemon

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// fakeSandbox is the minimal Sandbox a handler under test can observe: its
// identity and its Labels, which is exactly what infoOf and the profile check
// read. It is also extended to support Exec, WriteFile, ReadFile, and
// StartProcess for testing the exec handlers.
type fakeSandbox struct {
	sandbox.Sandbox
	info    sandbox.Info
	backend *fakeBackend // back-reference to store test data
}

func (f *fakeSandbox) Info() sandbox.Info { return f.info }

func (f *fakeSandbox) Stop(context.Context) error { return nil }

func (f *fakeSandbox) Exec(ctx context.Context, cmd sandbox.Command) (sandbox.Result, error) {
	f.backend.lastCommand = cmd
	return sandbox.Result{Stdout: []byte("output"), ExitCode: 0}, nil
}

func (f *fakeSandbox) WriteFile(ctx context.Context, path string, mode fs.FileMode, src io.Reader) error {
	data, _ := io.ReadAll(src)
	if f.backend.written == nil {
		f.backend.written = map[string]string{}
	}
	f.backend.written[path] = string(data)
	return nil
}

func (f *fakeSandbox) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	// Return a reader with some test content
	return io.NopCloser(strings.NewReader("file content")), nil
}

func (f *fakeSandbox) StartProcess(ctx context.Context, name string, cmd sandbox.Command) error {
	return nil
}

// fakeBackend stands in for a real provisioner. existing simulates sandboxes
// that were already created under some profile before the test began — the
// name -> profile label a real backend would report through Open and List.
type fakeBackend struct {
	sandbox.Backend
	createErr error
	created   map[string]sandbox.Spec
	existing  map[string]string // name -> profile label

	// createWinsUnderProfile simulates a concurrent Create winning the race
	// between this request's Open check and its own Create call: Create hands
	// back a live sandbox already labelled under a different profile than the
	// one this request resolved, exactly as Backend.Create's session-affinity
	// contract would when a name gets taken mid-request.
	createWinsUnderProfile string

	// Exec, WriteFile, ReadFile, and StartProcess test fields
	lastCommand sandbox.Command
	written     map[string]string // path -> content
}

func (f *fakeBackend) Create(_ context.Context, name string, opts ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	spec := sandbox.NewSpec(opts...)
	if f.created == nil {
		f.created = map[string]sandbox.Spec{}
	}
	f.created[name] = spec

	labels := spec.Labels
	if f.createWinsUnderProfile != "" {
		labels = map[string]string{labelProfile: f.createWinsUnderProfile}
	}
	return &fakeSandbox{info: sandbox.Info{Name: name, Image: spec.Image, Labels: labels}, backend: f}, nil
}

func (f *fakeBackend) Open(_ context.Context, name string) (sandbox.Sandbox, error) {
	profile, ok := f.existing[name]
	if !ok {
		return nil, sandbox.ErrNotFound
	}
	return &fakeSandbox{info: sandbox.Info{Name: name, Labels: map[string]string{labelProfile: profile}}, backend: f}, nil
}

func (f *fakeBackend) List(context.Context) ([]sandbox.Info, error) {
	out := make([]sandbox.Info, 0, len(f.existing))
	for name, profile := range f.existing {
		out = append(out, sandbox.Info{Name: name, Labels: map[string]string{labelProfile: profile}})
	}
	return out, nil
}

func (f *fakeBackend) Destroy(context.Context, string) error { return nil }

func (f *fakeBackend) DialPort(context.Context, string, int) (net.Conn, error) { return nil, nil }
func (f *fakeBackend) Reap(context.Context) ([]string, error)                  { return nil, nil }

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &Config{
		Socket: "/tmp/unused.sock",
		Profiles: map[string]Profile{
			"code-exec": {Image: "example.com/i@sha256:abc", Runtime: "runsc", MemoryMB: 2048, DiskMB: 1024},
			"browser":   {Image: "example.com/b@sha256:def", MemoryMB: 2048, DiskMB: 1024},
		},
	}
	return New(&fakeBackend{}, cfg)
}

func TestCreateAppliesProfilePolicy(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
	}

	spec := fake.created["a"]
	if spec.Runtime != "runsc" {
		t.Errorf("runtime = %q, want runsc from the profile", spec.Runtime)
	}
	if spec.Egress != sandbox.EgressNone {
		t.Errorf("egress = %v, want none", spec.Egress)
	}
	if spec.Image != "example.com/i@sha256:abc" {
		t.Errorf("image = %q, want the profile's", spec.Image)
	}
	if spec.Labels[labelProfile] != "code-exec" {
		t.Errorf("profile label = %q, want code-exec", spec.Labels[labelProfile])
	}

	var body brokerapi.Info
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Profile != "code-exec" {
		t.Errorf("response profile = %q, want code-exec", body.Profile)
	}
}

func TestCreateRejectsUnknownProfile(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"nope"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCreateOnExistingNameWithDifferentProfileConflicts(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "browser"} // name -> profile label

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestCreateOnExistingNameWithSameProfileSucceeds(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
	}
}

// The Open check happens before Create, not during it. A concurrent request
// can create the name under a different profile in between; Create then
// returns that sandbox rather than a fresh one, and the response must still
// refuse rather than report the caller's requested profile as though it held.
func TestCreateRaceLoserUnderDifferentProfileConflicts(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.createWinsUnderProfile = "browser"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"profile":"code-exec"`) {
		t.Error("response reports the requested profile rather than refusing — caller cannot tell it got the wrong policy")
	}
}

func TestCreateRequiresName(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCreateRejectsReservedProfileLabel(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec","labels":{"openbloxd.profile":"code-exec"}}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// The create-path versions of these two properties: Task 4 exercised decode
// and fail through a throwaway mux because handleCreate was still a stub.
// Now that it is real, the same properties must hold through the actual
// route.
func TestUnknownFieldOnCreateIsRejected(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec","runtime":"runc"}`))
	srv.Handler().ServeHTTP(rec, req)

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

func TestInternalErrorFromCreateDoesNotLeak(t *testing.T) {
	srv := newTestServer(t)
	srv.backend.(*fakeBackend).createErr = errStub("secret host path /var/lib/docker")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes",
		strings.NewReader(`{"name":"a","profile":"code-exec"}`))
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/var/lib/docker") {
		t.Error("internal detail leaked into the response body")
	}
}

func TestGetReturnsProfileFromLabel(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "browser"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/a", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var body brokerapi.Info
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Profile != "browser" {
		t.Errorf("profile = %q, want browser", body.Profile)
	}
}

func TestGetOnMissingSandboxIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/nope", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestListReturnsProfilePerSandbox(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "browser", "b": "code-exec"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sandboxes", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var body []brokerapi.Info
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 2 {
		t.Fatalf("got %d entries, want 2", len(body))
	}
	got := map[string]string{}
	for _, i := range body {
		got[i.Name] = i.Profile
	}
	if got["a"] != "browser" || got["b"] != "code-exec" {
		t.Errorf("name -> profile = %+v", got)
	}
}

func TestDestroyReturnsNoContent(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/sandboxes/a", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestStopHaltsAnExistingSandbox(t *testing.T) {
	srv := newTestServer(t)
	fake := srv.backend.(*fakeBackend)
	fake.existing = map[string]string{"a": "browser"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/a/stop", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body %s", rec.Code, rec.Body.String())
	}
}

func TestStopOnMissingSandboxIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/nope/stop", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
