package preview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialer opens a byte stream to a port inside a named sandbox.
type Dialer interface {
	DialPort(ctx context.Context, name string, port int) (net.Conn, error)
}

// RoutePrefix is where a Handler expects to be mounted. Routes below it are
// "<prefix>/<sandbox>/<port>/<path…>".
const RoutePrefix = "/preview"

// Handler proxies authenticated requests to ports inside sandboxes.
//
// Mount it on a server the caller owns:
//
//	mux.Handle(preview.RoutePrefix+"/", preview.NewHandler(backend, signer))
//
// openblox does not run the server. What the outside world may reach, on what
// address, behind what TLS, is a deployment decision, and a library that made it
// would be a service.
type Handler struct {
	dialer Dialer
	signer *Signer
	proxy  *httputil.ReverseProxy

	// revoked holds tokens withdrawn before their expiry, keyed by token, valued
	// by the expiry after which the entry is worthless.
	mu      sync.Mutex
	revoked map[string]time.Time
}

// NewHandler returns a Handler serving previews for sandboxes reachable through
// dialer, authenticated with signer.
func NewHandler(dialer Dialer, signer *Signer) *Handler {
	h := &Handler{dialer: dialer, signer: signer, revoked: map[string]time.Time{}}
	h.proxy = &httputil.ReverseProxy{
		Rewrite: rewrite,
		// Each idle connection is a relay process in a sandbox plus a Docker
		// connection, and every (sandbox, port) has its own pool — so idle
		// connections are bounded in number and in time.
		Transport: &http.Transport{
			DialContext:     h.dial,
			MaxIdleConns:    64,
			IdleConnTimeout: 30 * time.Second,
		},
		// Stream rather than buffer. A preview commonly carries server-sent
		// events or a long-lived agent protocol, and buffering those means the
		// client sees nothing until the response ends, which it never does.
		FlushInterval: -1,
		ErrorHandler:  proxyError,
	}
	return h
}

// Revoke withdraws a token before it expires.
//
// This is best-effort by construction. Tokens are self-describing and validated
// locally, so nothing has to be consulted to accept one — the same property that
// removes the control plane means a revocation lives only in the process that
// recorded it. Expiry is the bound that always holds; keep preview lifetimes
// short and treat this as prompt cleanup, not containment.
func (h *Handler) Revoke(token string) {
	expiresAt, ok := ExpiresAt(token)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.revoked[token] = expiresAt
	// Entries past their expiry are already refused on the strength of the
	// expiry alone, so the set only ever holds live tokens.
	for t, exp := range h.revoked {
		if time.Now().After(exp) {
			delete(h.revoked, t)
		}
	}
}

func (h *Handler) isRevoked(token string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.revoked[token]
	return ok
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, port, rest, ok := parseRoute(r.URL.EscapedPath())
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	token := bearerToken(r)
	if token == "" {
		// Advertise the scheme so a caller who sent nothing learns what to send,
		// without telling one who sent a bad token anything about why.
		w.Header().Set("WWW-Authenticate", `Bearer realm="openblox preview"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.signer.Verify(token, name, port, time.Now()); err != nil || h.isRevoked(token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// The credential authorises the hop to the sandbox and must not travel into
	// it: code in the sandbox should never see a token that grants access to
	// itself, or to anything else.
	r = r.Clone(withRoute(r.Context(), name, port))
	r.Header.Del("Authorization")
	r.URL.Path = rest
	r.URL.RawPath = ""

	h.proxy.ServeHTTP(w, r)
}

// dial reaches the sandbox named by the request's own route. There is no host
// to resolve, because the sandbox has no network; the address net/http passes
// is the route's pool key, and must match the route or the dial is refused.
func (h *Handler) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	name, port, ok := routeFrom(ctx)
	if !ok {
		return nil, errors.New("preview: request reached the dialer without a route")
	}
	if want := net.JoinHostPort(upstreamHost(name, port), "80"); addr != want {
		return nil, fmt.Errorf("preview: dial for %q does not match the authorised route", addr)
	}
	return h.dialer.DialPort(ctx, name, port)
}

// upstreamHost is the per-route host the transport pools connections under.
//
// net/http reuses an idle keep-alive connection for any later request to the
// same host. Every route must therefore have a host of its own: a shared one
// would hand a connection into sandbox A to a request authorised only for
// sandbox B. The name is hashed because it is arbitrary caller text and a
// hostname label is not.
func upstreamHost(name string, port int) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%s-%d.sandbox.invalid", hex.EncodeToString(sum[:16]), port)
}

func rewrite(pr *httputil.ProxyRequest) {
	pr.Out.URL.Scheme = "http"
	// The route was attached by ServeHTTP after the token was verified; see
	// upstreamHost for why the host must be unique to it.
	name, port, _ := routeFrom(pr.In.Context())
	pr.Out.URL.Host = upstreamHost(name, port)
	pr.Out.Host = "localhost"
	// Do not forward X-Forwarded-For and friends: they would tell code in the
	// sandbox the client's address, which is not its business.
	pr.Out.Header.Del("X-Forwarded-For")
}

func proxyError(w http.ResponseWriter, _ *http.Request, err error) {
	// The detail stays out of the response: it would describe the host's
	// internals to whoever is holding the token.
	_ = err
	http.Error(w, "preview unavailable", http.StatusBadGateway)
}

// parseRoute splits "<prefix>/<sandbox>/<port>/<rest…>".
func parseRoute(path string) (name string, port int, rest string, ok bool) {
	trimmed, found := strings.CutPrefix(path, RoutePrefix+"/")
	if !found {
		return "", 0, "", false
	}
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) < 2 {
		return "", 0, "", false
	}
	name, err := url.PathUnescape(parts[0])
	if err != nil || name == "" {
		return "", 0, "", false
	}
	port, err = strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", false
	}
	rest = "/"
	if len(parts) == 3 {
		rest += parts[2]
	}
	return name, port, rest, true
}

// URL returns the address a preview for port in a sandbox is served at, given
// the base address the Handler is reachable on.
func URL(base, sandboxName string, port int) string {
	return fmt.Sprintf("%s%s/%s/%d/",
		strings.TrimSuffix(base, "/"), RoutePrefix, url.PathEscape(sandboxName), port)
}

func bearerToken(r *http.Request) string {
	// Header only. A credential in the query string is copied into access logs,
	// browser history, and the Referer of every link the page follows.
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(token)
}

type routeKey struct{}

type route struct {
	name string
	port int
}

func withRoute(ctx context.Context, name string, port int) context.Context {
	return context.WithValue(ctx, routeKey{}, route{name: name, port: port})
}

func routeFrom(ctx context.Context) (string, int, bool) {
	r, ok := ctx.Value(routeKey{}).(route)
	return r.name, r.port, ok
}
