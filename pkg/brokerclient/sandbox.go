package brokerclient

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
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

// WriteFile writes src to path inside the sandbox.
//
// mode is accepted to satisfy the interface but has no effect over the
// broker: openbloxd writes every file 0644 regardless of what is asked
// (internal/daemon/exec.go's filePerm), because the wire request carries no
// mode field. That is the daemon's contract, not something this client can
// widen.
func (s *brokerSandbox) WriteFile(ctx context.Context, path string, _ fs.FileMode, src io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, baseURL+s.filesRoute(path), src)
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

// ReadFile opens path inside the sandbox for reading. The caller must close
// the returned reader.
func (s *brokerSandbox) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+s.filesRoute(path), nil)
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
	return nil
}

// route builds a path under this sandbox's own resource.
func (s *brokerSandbox) route(suffix string) string {
	return "/sandboxes/" + pathEscape(s.name) + suffix
}

// filesRoute builds the files path for an absolute in-sandbox path. The
// leading slash is stripped and re-added server-side (see
// internal/daemon/exec.go), matching the wildcard route
// "/sandboxes/{name}/files/{path...}".
func (s *brokerSandbox) filesRoute(path string) string {
	return s.route("/files/") + strings.TrimPrefix(path, "/")
}
