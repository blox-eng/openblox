package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Backend is what the daemon needs from a provisioner: the library contract
// plus the two methods outside it that the broker exposes.
type Backend interface {
	sandbox.Backend
	DialPort(ctx context.Context, name string, port int) (net.Conn, error)
	Reap(ctx context.Context) ([]string, error)
}

// Server routes broker requests onto a Backend under a fixed policy.
type Server struct {
	backend Backend
	cfg     *Config
}

// New returns a Server. It does not listen; see Listen and Handler.
func New(backend Backend, cfg *Config) *Server {
	return &Server{backend: backend, cfg: cfg}
}

// Handler returns the route table.
//
// No path carries a version prefix: the daemon and its client ship together and
// speak over a local socket, so there is no independently versioned consumer to
// protect. A header can version this later without a guess baked into a path.
//
// The lifecycle handlers (sandboxes.go) are real; the rest are stubs Tasks 6-7
// replace, and until then answer ErrNotFound so the route table itself,
// decode, and fail can be exercised end to end.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sandboxes", s.handleCreate)
	mux.HandleFunc("GET /sandboxes", s.handleList)
	mux.HandleFunc("GET /sandboxes/{name}", s.handleGet)
	mux.HandleFunc("DELETE /sandboxes/{name}", s.handleDestroy)
	mux.HandleFunc("POST /sandboxes/{name}/stop", s.handleStop)
	mux.HandleFunc("POST /sandboxes/{name}/exec", s.handleExec)
	mux.HandleFunc("PUT /sandboxes/{name}/files/{path...}", s.handleWriteFile)
	mux.HandleFunc("GET /sandboxes/{name}/files/{path...}", s.handleReadFile)
	mux.HandleFunc("POST /sandboxes/{name}/processes", s.handleStartProcess)
	mux.HandleFunc("GET /sandboxes/{name}/dial/{port}", s.handleDial)
	mux.HandleFunc("GET /profiles", s.handleProfiles)
	return mux
}

func (s *Server) handleExec(w http.ResponseWriter, _ *http.Request) { fail(w, sandbox.ErrNotFound) }
func (s *Server) handleWriteFile(w http.ResponseWriter, _ *http.Request) {
	fail(w, sandbox.ErrNotFound)
}
func (s *Server) handleReadFile(w http.ResponseWriter, _ *http.Request) { fail(w, sandbox.ErrNotFound) }
func (s *Server) handleStartProcess(w http.ResponseWriter, _ *http.Request) {
	fail(w, sandbox.ErrNotFound)
}
func (s *Server) handleDial(w http.ResponseWriter, _ *http.Request)     { fail(w, sandbox.ErrNotFound) }
func (s *Server) handleProfiles(w http.ResponseWriter, _ *http.Request) { fail(w, sandbox.ErrNotFound) }

// decode reads a strict JSON body. An unknown field is a 400 and not an
// ignored field: silently accepting one is how a request field that must not
// exist comes back, because the caller looks like it is being obeyed.
func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		fail(w, fmt.Errorf("%w: %s", sandbox.ErrInvalid, err.Error()))
		return v, false
	}
	return v, true
}

// respond writes a JSON body with the given status.
func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// fail classifies err and answers with it.
//
// An unrecognised error is logged in full and reported as a bare "internal
// error". The detail would describe the host's internals to whoever is holding
// the socket, which is the same discipline preview.proxyError follows.
func fail(w http.ResponseWriter, err error) {
	kind, status := brokerapi.KindOf(err)
	message := err.Error()
	if kind == brokerapi.KindInternal {
		slog.Error("openbloxd request failed", slog.Any("error", err))
		message = "internal error"
	}
	respond(w, status, brokerapi.Error{Message: message, Kind: kind})
}
