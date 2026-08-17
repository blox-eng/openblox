package brokerclient

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// DefaultPreviewTTL applies when Expose is asked for no particular lifetime.
// It mirrors pkg/docker's default rather than importing it: brokerclient
// depends on nothing that needs a Docker socket, and docker.DefaultPreviewTTL
// is the one constant in that package that isn't.
const DefaultPreviewTTL = 10 * time.Minute

// brokerSandbox is a handle to a sandbox openbloxd manages.
type brokerSandbox struct {
	client *Client
	// name is the resolved sandbox name, kept separately from info because
	// Expose and Revoke sign against it without another round trip.
	name string
	info sandbox.Info
}

func (s *brokerSandbox) Info() sandbox.Info { return s.info }

// Exec runs a command to completion and returns its output.
func (s *brokerSandbox) Exec(ctx context.Context, cmd sandbox.Command) (sandbox.Result, error) {
	if err := cmd.Validate(); err != nil {
		return sandbox.Result{}, err
	}
	// brokerapi.ExecRequest has no field for it: the wire contract does not
	// carry stdin. Silently discarding it here would mislead a caller into
	// thinking a program that reads stdin got what it asked for.
	if cmd.Stdin != nil {
		return sandbox.Result{}, fmt.Errorf("%w: exec stdin is not supported over the broker", sandbox.ErrInvalid)
	}

	req := brokerapi.ExecRequest{Argv: cmd.Argv, Env: cmd.Env, Dir: cmd.Dir}
	if cmd.Timeout > 0 {
		req.Timeout = cmd.Timeout.String()
	}

	var resp brokerapi.ExecResponse
	if err := s.client.do(ctx, http.MethodPost, s.route("/exec"), req, &resp); err != nil {
		return sandbox.Result{}, err
	}
	return sandbox.Result{Stdout: resp.Stdout, Stderr: resp.Stderr, ExitCode: resp.ExitCode}, nil
}

// WriteFile writes src to dest inside the sandbox.
//
// dest must be absolute — the same rule docker.dockerSandbox.WriteFile
// enforces (pkg/docker/sandbox.go). Checking it here, before the request is
// even built, matches the library's behaviour: a relative path is refused
// outright rather than silently reinterpreted against the wrong root. See
// filesRoute for how the wire encoding keeps this checkable independently on
// the daemon side too.
//
// mode is accepted to satisfy the interface but has no effect over the
// broker: openbloxd writes every file 0644 regardless of what is asked
// (internal/daemon/exec.go's filePerm), because the wire request carries no
// mode field. That is the daemon's contract, not something this client can
// widen.
func (s *brokerSandbox) WriteFile(ctx context.Context, dest string, _ fs.FileMode, src io.Reader) error {
	if !path.IsAbs(dest) {
		return fmt.Errorf("%w: path %q is not absolute", sandbox.ErrInvalid, dest)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, baseURL+s.filesRoute(dest), src)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := s.client.http.Do(req)
	if err != nil {
		return fmt.Errorf("openbloxd: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errorFrom(resp)
	}
	return nil
}

// ReadFile opens dest inside the sandbox for reading. The caller must close
// the returned reader. See WriteFile for why dest must be absolute.
func (s *brokerSandbox) ReadFile(ctx context.Context, dest string) (io.ReadCloser, error) {
	if !path.IsAbs(dest) {
		return nil, fmt.Errorf("%w: path %q is not absolute", sandbox.ErrInvalid, dest)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+s.filesRoute(dest), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openbloxd: request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, errorFrom(resp)
	}
	return resp.Body, nil
}

// StartProcess starts cmd as a detached background process under name.
func (s *brokerSandbox) StartProcess(ctx context.Context, name string, cmd sandbox.Command) error {
	if cmd.Stdin != nil {
		return fmt.Errorf("%w: process stdin is not supported over the broker", sandbox.ErrInvalid)
	}
	req := brokerapi.ProcessRequest{Name: name, Argv: cmd.Argv, Env: cmd.Env, Dir: cmd.Dir}
	return s.client.do(ctx, http.MethodPost, s.route("/processes"), req, nil)
}

// Stop halts the sandbox without discarding it.
func (s *brokerSandbox) Stop(ctx context.Context) error {
	return s.client.do(ctx, http.MethodPost, s.route("/stop"), nil, nil)
}

// Expose returns a signed, expiring URL for a port inside the sandbox.
//
// Nothing is opened by this call, and nothing here reaches openbloxd: it
// signs a name, a port and an expiry with the client's own key. There is no
// /expose endpoint, because the daemon holds no signing key at all — the key
// lives only in the process that also verifies previews.
func (s *brokerSandbox) Expose(_ context.Context, port int, ttl time.Duration) (sandbox.Preview, error) {
	if s.client.signer == nil {
		return sandbox.Preview{}, fmt.Errorf(
			"%w: previews are not configured; pass brokerclient.WithPreviews to New", sandbox.ErrInvalid)
	}
	if port < 1 || port > 65535 {
		return sandbox.Preview{}, fmt.Errorf("%w: port %d is out of range", sandbox.ErrInvalid, port)
	}

	expiresAt := time.Now().Add(preview.ClampTTL(ttl, DefaultPreviewTTL)).UTC()
	token, err := s.client.signer.Sign(s.name, port, expiresAt)
	if err != nil {
		return sandbox.Preview{}, fmt.Errorf("%w: %w", sandbox.ErrInvalid, err)
	}

	return sandbox.Preview{
		URL:       preview.URL(s.client.previewBase, s.name, port),
		Token:     token,
		Port:      port,
		ExpiresAt: expiresAt,
	}, nil
}

// Revoke invalidates a token returned by Expose before it expires.
func (s *brokerSandbox) Revoke(_ context.Context, port int, token string) error {
	if s.client.signer == nil {
		return fmt.Errorf("%w: previews are not configured", sandbox.ErrInvalid)
	}
	// Refuse to act on a token this sandbox did not issue, so one sandbox
	// cannot revoke another's credentials by guessing.
	if err := s.client.signer.Verify(token, s.name, port, time.Now()); err != nil {
		return fmt.Errorf("%w: %w", sandbox.ErrInvalid, err)
	}
	// previewHandler is set whenever signer is (see WithPreviews): it is the
	// same instance PreviewHandler returns, which is what makes this take
	// effect for traffic actually being served rather than just verifying a
	// signature and reporting success for a revocation nothing enforces.
	s.client.previewHandler.Revoke(token)
	return nil
}

// route builds a path under this sandbox's own resource.
func (s *brokerSandbox) route(suffix string) string {
	return "/sandboxes/" + pathEscape(s.name) + suffix
}

// filesRoute builds the files path for an absolute in-sandbox path.
//
// dest is percent-escaped in full (not just its leading slash) so it survives
// inside the "{path...}" wildcard of "/sandboxes/{name}/files/{path...}"
// byte-identical, whatever it contains. url.PathEscape escapes every "/" as
// "%2F" along with "?", "#", spaces and anything else that would otherwise be
// read as a path separator or query/fragment delimiter — a "?" or "#" left
// unescaped truncates dest at the mux before it ever reaches the wildcard,
// silently writing or reading the wrong file rather than failing loudly. The
// wildcard decodes every "%XX" back on the way in, so r.PathValue("path") on
// the server is exactly dest, unmodified — see internal/daemon/exec.go, which
// checks path.IsAbs on that value directly rather than reconstructing it from
// an assumption.
func (s *brokerSandbox) filesRoute(dest string) string {
	return s.route("/files/") + url.PathEscape(dest)
}
