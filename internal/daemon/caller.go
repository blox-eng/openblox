package daemon

import (
	"context"
	"log/slog"
	"net/http"
)

// Transport names the way a request arrived.
const (
	TransportUnix = "unix"
	TransportTLS  = "tls"
)

// Caller is who made a request.
//
// Nothing consumes this yet. It exists anyway because a transport that
// discards the caller's identity has to be reopened to add per-caller quotas
// or an audit trail, and the place to record identity is where it is still
// available.
//
// Transport is carried explicitly rather than inferred from an empty Name: a
// log line for a security boundary should say whether a request arrived
// locally or over a network, not leave it to be deduced.
type Caller struct {
	Transport string
	Name      string
}

type callerKey struct{}

// WithCaller records the caller on the request context, over every transport.
//
// Name is empty for a Unix caller because SO_PEERCRED is unimplemented; that
// is the local transport's identity seam and is unrelated to this one.
func WithCaller(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := Caller{Transport: TransportUnix}
		if r.TLS != nil {
			c.Transport = TransportTLS
			if len(r.TLS.PeerCertificates) > 0 {
				c.Name = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			// Logged only for network callers. The Unix socket is the
			// high-volume local path and its behaviour is deliberately
			// unchanged; a remote request is the one worth an audit line.
			slog.Info("openbloxd request",
				slog.String("caller", c.Name),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path))
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}

// CallerFrom returns the caller recorded by WithCaller.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}
