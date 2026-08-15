package daemon

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"time"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// filePerm is the mode written files get. The sandbox runs unprivileged and
// every writable mount is noexec, so this is ordinary read/write.
const filePerm fs.FileMode = 0o644

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[brokerapi.ExecRequest](w, r)
	if !ok {
		return
	}
	var timeout time.Duration
	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil {
			fail(w, fmt.Errorf("%w: timeout %q: %s", sandbox.ErrInvalid, req.Timeout, err))
			return
		}
		timeout = d
	}

	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}

	// The sandbox clamps the timeout to the profile's ceiling through the
	// library's ResolveTimeout, so a caller can only narrow it.
	res, err := sb.Exec(r.Context(), sandbox.Command{
		Argv:    req.Argv,
		Env:     req.Env,
		Dir:     req.Dir,
		Timeout: timeout,
	})
	if err != nil {
		fail(w, err)
		return
	}
	respond(w, http.StatusOK, brokerapi.ExecResponse{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: res.ExitCode,
	})
}

// filePath reads the wildcard path segment as the caller's client sent it.
//
// It is used exactly as received, with no "/" prepended: brokerclient's
// filesRoute percent-encodes the leading slash of an absolute path so it
// survives the wildcard unmangled (net/http's ServeMux would otherwise
// redirect-and-collapse a literal doubled slash), so r.PathValue("path")
// already equals the caller's dest. Prepending "/" here — the previous
// behaviour — would make every request look absolute regardless of what was
// actually sent, silently rerooting a relative path instead of refusing it.
// The explicit path.IsAbs check below is the same rule
// docker.dockerSandbox.WriteFile/ReadFile enforce (pkg/docker/sandbox.go),
// applied independently of whether the caller across the socket is
// brokerclient or something else entirely.
func filePath(r *http.Request) (string, error) {
	p := r.PathValue("path")
	if !path.IsAbs(p) {
		return "", fmt.Errorf("%w: path %q is not absolute", sandbox.ErrInvalid, p)
	}
	return p, nil
}

func (s *Server) handleWriteFile(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	dest, err := filePath(r)
	if err != nil {
		fail(w, err)
		return
	}
	// Stream the body straight through: a sandbox payload can be large, and
	// buffering it here would put the caller's file in the daemon's heap.
	if err := sb.WriteFile(r.Context(), dest, filePerm, r.Body); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReadFile(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	dest, err := filePath(r)
	if err != nil {
		fail(w, err)
		return
	}
	rc, err := sb.ReadFile(r.Context(), dest)
	if err != nil {
		fail(w, err)
		return
	}
	defer func() { _ = rc.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	// An error partway through cannot change the status: it is already sent.
	// Log it and drop the connection rather than append a lie to the body.
	if _, err := io.Copy(w, rc); err != nil {
		slog.Warn("openbloxd: read-file stream truncated", slog.Any("error", err))
	}
}

func (s *Server) handleStartProcess(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[brokerapi.ProcessRequest](w, r)
	if !ok {
		return
	}
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	err = sb.StartProcess(r.Context(), req.Name, sandbox.Command{
		Argv: req.Argv,
		Env:  req.Env,
		Dir:  req.Dir,
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
