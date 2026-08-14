package brokerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// baseURL is a placeholder: every request is dialled straight to socketPath
// regardless of what host or scheme the URL names. It exists only because
// net/http requires a well-formed URL to build a request from.
const baseURL = "http://openbloxd"

// Client reaches openbloxd over its Unix socket. It satisfies sandbox.Backend
// so it can stand in for a Docker-backed one without the caller changing any
// other code.
type Client struct {
	http *http.Client

	// socket is redialled directly by DialPort, which needs a raw connection
	// outside the pooled http.Client — see dial.go.
	socket string

	// signer and previewBase are set only when WithPreviews was passed. Expose
	// and Revoke fail cleanly when they are nil, rather than minting a URL
	// nothing serves.
	signer      *preview.Signer
	previewBase string
}

// New returns a Client that dials openbloxd at socketPath.
func New(socketPath string, opts ...Option) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("%w: socket path is empty", sandbox.ErrInvalid)
	}
	c := &Client{
		socket: socketPath,
		http: &http.Client{
			Transport: &http.Transport{
				// The address net/http computed is discarded: there is exactly one
				// place this client ever talks to, and it is not on the network.
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Close releases the client's own resources. It does not touch any sandbox,
// which is openbloxd's to manage and outlives this process either way.
func (c *Client) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// Create returns a running sandbox for name, creating it if absent.
//
// Every CreateOption that would set host policy — runtime, egress, image,
// user, resources, lifetime — is daemon configuration now, chosen by profile.
// Passing one here is rejected rather than ignored: see policyFields.
func (c *Client) Create(ctx context.Context, name string, opts ...sandbox.CreateOption) (sandbox.Sandbox, error) {
	spec := sandbox.NewSpec(opts...)
	profile := spec.Labels[profileLabel]
	if profile == "" {
		return nil, fmt.Errorf("%w: no profile; pass brokerclient.WithProfile", sandbox.ErrInvalid)
	}
	if set := policyFields(spec); len(set) > 0 {
		return nil, fmt.Errorf(
			"%w: %s %s daemon policy and cannot be set per-request; configure them in the profile",
			sandbox.ErrInvalid, strings.Join(set, ", "), plural(len(set)))
	}

	labels := maps.Clone(spec.Labels)
	delete(labels, profileLabel)

	req := brokerapi.CreateRequest{
		Name:    name,
		Profile: profile,
		Env:     spec.Env,
		Labels:  labels,
	}
	var info brokerapi.Info
	if err := c.do(ctx, http.MethodPost, "/sandboxes", req, &info); err != nil {
		return nil, err
	}
	return c.sandboxFrom(info), nil
}

// Open returns an existing sandbox, or ErrNotFound.
func (c *Client) Open(ctx context.Context, name string) (sandbox.Sandbox, error) {
	var info brokerapi.Info
	if err := c.do(ctx, http.MethodGet, "/sandboxes/"+pathEscape(name), nil, &info); err != nil {
		return nil, err
	}
	return c.sandboxFrom(info), nil
}

// List returns every sandbox openbloxd manages.
func (c *Client) List(ctx context.Context) ([]sandbox.Info, error) {
	var infos []brokerapi.Info
	if err := c.do(ctx, http.MethodGet, "/sandboxes", nil, &infos); err != nil {
		return nil, err
	}
	out := make([]sandbox.Info, 0, len(infos))
	for _, i := range infos {
		out = append(out, infoFrom(i))
	}
	return out, nil
}

// Destroy removes a sandbox. Destroying an absent sandbox is not an error.
func (c *Client) Destroy(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/sandboxes/"+pathEscape(name), nil, nil)
}

// sandboxFrom builds a handle from a wire Info, keeping the resolved name so
// Expose and Revoke — which never touch the daemon — can address the sandbox
// without another round trip.
func (c *Client) sandboxFrom(info brokerapi.Info) *brokerSandbox {
	return &brokerSandbox{client: c, name: info.Name, info: infoFrom(info)}
}

func infoFrom(i brokerapi.Info) sandbox.Info {
	return sandbox.Info{
		Name:      i.Name,
		ID:        i.ID,
		Image:     i.Image,
		State:     sandbox.State(i.State),
		CreatedAt: i.CreatedAt,
		Labels:    i.Labels,
	}
}

// do performs a JSON round trip: reqBody is marshalled as the request body
// (skipped when nil), and a 2xx response is decoded into respBody (skipped
// when nil). A non-2xx response is decoded as brokerapi.Error and mapped back
// through brokerapi.ErrorFor, so a caller's errors.Is checks against the
// library's sentinels behave the same whether they are talking to the broker
// or to the library directly.
func (c *Client) do(ctx context.Context, method, path string, reqBody, respBody any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("openbloxd: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errorFrom(resp)
	}
	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// errorFrom decodes a non-2xx response body as brokerapi.Error and maps it
// back to the matching sandbox/brokerapi sentinel. A body that does not even
// parse still becomes ErrInternal rather than a bare decode error, so a
// caller's errors.Is checks keep working even against a response the daemon
// itself never produces (a proxy or the socket's own error page).
func errorFrom(resp *http.Response) error {
	var wireErr brokerapi.Error
	if err := json.NewDecoder(resp.Body).Decode(&wireErr); err != nil {
		return fmt.Errorf("%w: openbloxd returned status %d", brokerapi.ErrInternal, resp.StatusCode)
	}
	return fmt.Errorf("%w: %s", brokerapi.ErrorFor(wireErr.Kind), wireErr.Message)
}

// pathEscape encodes a sandbox name for a single URL path segment.
func pathEscape(name string) string { return url.PathEscape(name) }

// Compile-time proof the broker client satisfies the same contract the
// Docker backend does, and needs no adapter to serve preview.NewHandler.
var (
	_ sandbox.Backend = (*Client)(nil)
	_ sandbox.Sandbox = (*brokerSandbox)(nil)
	_ preview.Dialer  = (*Client)(nil)
)
