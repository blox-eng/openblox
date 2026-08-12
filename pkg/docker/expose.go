package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// DefaultPreviewTTL applies when Expose is asked for no particular lifetime.
const DefaultPreviewTTL = 10 * time.Minute

// previews holds what a backend needs to issue preview credentials. It is nil
// unless the caller configured one, and Expose fails cleanly when it is: a
// backend that cannot be reached should say so rather than hand back a URL
// nothing serves.
type previews struct {
	signer  *preview.Signer
	baseURL string
	handler *preview.Handler
}

// WithPreviews enables Expose, signing credentials with key and serving them
// under baseURL — the address, including scheme, that the returned Handler is
// reachable on from wherever the preview will be opened.
//
// The key must be at least preview.MinKeyBytes of CSPRNG output, and the same
// key everywhere previews are minted or served.
func WithPreviews(key []byte, baseURL string) Option {
	return func(b *Backend) error {
		signer, err := preview.NewSigner(key)
		if err != nil {
			return err
		}
		if baseURL == "" {
			return fmt.Errorf("%w: preview base URL is empty", sandbox.ErrInvalid)
		}
		b.previews = &previews{
			signer:  signer,
			baseURL: baseURL,
			handler: preview.NewHandler(b, signer),
		}
		return nil
	}
}

// PreviewHandler returns the HTTP handler that serves this backend's previews,
// or nil if previews were not configured. Mount it at preview.RoutePrefix.
//
// openblox does not run a server. Which address it listens on, behind what TLS,
// and who can reach it are deployment decisions.
func (b *Backend) PreviewHandler() *preview.Handler {
	if b.previews == nil {
		return nil
	}
	return b.previews.handler
}

// Expose returns a signed, expiring URL for a port inside the sandbox.
//
// Nothing is opened by this call. The port becomes reachable only through the
// preview handler, only for the lifetime of the credential, and only to whoever
// holds it — the sandbox itself gains no network.
func (s *dockerSandbox) Expose(_ context.Context, port int, ttl time.Duration) (sandbox.Preview, error) {
	if s.previews == nil {
		return sandbox.Preview{}, fmt.Errorf(
			"%w: previews are not configured; pass docker.WithPreviews to New", sandbox.ErrInvalid)
	}
	if port < 1 || port > 65535 {
		return sandbox.Preview{}, fmt.Errorf("%w: port %d is out of range", sandbox.ErrInvalid, port)
	}

	expiresAt := time.Now().Add(preview.ClampTTL(ttl, DefaultPreviewTTL)).UTC()
	token, err := s.previews.signer.Sign(s.info.Name, port, expiresAt)
	if err != nil {
		return sandbox.Preview{}, fmt.Errorf("%w: %w", sandbox.ErrInvalid, err)
	}

	return sandbox.Preview{
		URL:       preview.URL(s.previews.baseURL, s.info.Name, port),
		Token:     token,
		Port:      port,
		ExpiresAt: expiresAt,
	}, nil
}

// Revoke withdraws a token before it expires. See preview.Handler.Revoke for why
// expiry, not this, is the bound that always holds.
func (s *dockerSandbox) Revoke(_ context.Context, port int, token string) error {
	if s.previews == nil {
		return fmt.Errorf("%w: previews are not configured", sandbox.ErrInvalid)
	}
	// Refuse to act on a token this sandbox did not issue, so one sandbox cannot
	// revoke another's credentials by guessing.
	if err := s.previews.signer.Verify(token, s.info.Name, port, time.Now()); err != nil {
		return fmt.Errorf("%w: %w", sandbox.ErrInvalid, err)
	}
	s.previews.handler.Revoke(token)
	return nil
}
