package docker

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

const previewBase = "https://preview.example"

var unitPreviewKey = bytes.Repeat([]byte{7}, preview.MinKeyBytes)

// refusingDialer stands in for the backend: any request that gets past the
// handler's credential check fails at the dial, so a 502 means "authorised".
type refusingDialer struct{}

// DialPort refuses every dial.
func (refusingDialer) DialPort(context.Context, string, int) (net.Conn, error) {
	return nil, errors.New("no sandbox in this test")
}

// previewSandboxes returns two sandboxes that share one preview configuration,
// as two sandboxes of one backend do.
func previewSandboxes(t *testing.T) (box, other *dockerSandbox) {
	t.Helper()
	signer, err := preview.NewSigner(unitPreviewKey)
	if err != nil {
		t.Fatal(err)
	}
	p := &previews{signer: signer, baseURL: previewBase, handler: preview.NewHandler(refusingDialer{}, signer)}
	return &dockerSandbox{info: sandbox.Info{Name: "box"}, previews: p},
		&dockerSandbox{info: sandbox.Info{Name: "other"}, previews: p}
}

// serve sends one request for a preview through the sandbox's handler and
// returns the status.
func serve(s *dockerSandbox, p sandbox.Preview) int {
	req := httptest.NewRequest(http.MethodGet, p.URL, nil)
	req.Header.Set("Authorization", "Bearer "+p.Token)
	rec := httptest.NewRecorder()
	s.previews.handler.ServeHTTP(rec, req)
	return rec.Code
}

// A short key or a missing base URL fails at New, not at the first Expose.
func TestWithPreviewsRejectsABadConfiguration(t *testing.T) {
	if err := WithPreviews(unitPreviewKey[:preview.MinKeyBytes-1], previewBase)(&Backend{}); err == nil {
		t.Error("a key shorter than preview.MinKeyBytes was accepted")
	}
	if err := WithPreviews(unitPreviewKey, "")(&Backend{}); !errors.Is(err, sandbox.ErrInvalid) {
		t.Errorf("empty base URL = %v, want ErrInvalid", err)
	}
}

// Callers mount the handler only when it is non-nil.
func TestPreviewHandlerExistsOnlyWhenConfigured(t *testing.T) {
	if h := (&Backend{}).PreviewHandler(); h != nil {
		t.Error("a backend without previews returned a handler")
	}
	b := &Backend{}
	if err := WithPreviews(unitPreviewKey, previewBase)(b); err != nil {
		t.Fatal(err)
	}
	if b.PreviewHandler() == nil {
		t.Error("a backend with previews returned no handler")
	}
}

// A backend with no preview server must say so, and say how to fix it, rather
// than hand back a URL nothing serves.
func TestExposeWithoutPreviewsSaysHowToEnableThem(t *testing.T) {
	s := &dockerSandbox{info: sandbox.Info{Name: "box"}}

	_, err := s.Expose(context.Background(), 8080, time.Minute)

	if !errors.Is(err, sandbox.ErrInvalid) || !strings.Contains(err.Error(), "WithPreviews") {
		t.Fatalf("Expose = %v, want ErrInvalid naming WithPreviews", err)
	}
	if err := s.Revoke(context.Background(), 8080, "token"); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("Revoke = %v, want ErrInvalid", err)
	}
}

func TestExposeRejectsPortsOutOfRange(t *testing.T) {
	box, _ := previewSandboxes(t)
	for _, port := range []int{-1, 0, 65536} {
		if _, err := box.Expose(context.Background(), port, time.Minute); !errors.Is(err, sandbox.ErrInvalid) {
			t.Errorf("Expose(%d) = %v, want ErrInvalid", port, err)
		}
	}
}

// The credential opens this sandbox's port and nothing else: not another
// port, not another sandbox.
func TestExposeMintsACredentialForThisSandboxAndPortOnly(t *testing.T) {
	box, other := previewSandboxes(t)

	p, err := box.Expose(context.Background(), 8080, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if p.URL != preview.URL(previewBase, "box", 8080) || p.Port != 8080 {
		t.Fatalf("preview = %s port %d, want box's 8080", p.URL, p.Port)
	}
	if code := serve(box, p); code != http.StatusBadGateway {
		t.Fatalf("own preview = %d, want it authorised (502 from the stand-in dialer)", code)
	}
	for name, stolen := range map[string]sandbox.Preview{
		"another port":    {URL: preview.URL(previewBase, "box", 8081), Token: p.Token},
		"another sandbox": {URL: preview.URL(previewBase, "other", 8080), Token: p.Token},
	} {
		if code := serve(other, stolen); code != http.StatusUnauthorized {
			t.Errorf("token used on %s = %d, want 401", name, code)
		}
	}
}

// No lifetime gets the default, and no credential outlives preview.MaxTTL.
func TestExposeBoundsTheLifetime(t *testing.T) {
	box, _ := previewSandboxes(t)
	for _, tc := range []struct {
		ask, want time.Duration
	}{
		{5 * time.Minute, 5 * time.Minute},
		{0, DefaultPreviewTTL},
		{-time.Minute, DefaultPreviewTTL},
		{7 * 24 * time.Hour, preview.MaxTTL},
	} {
		before := time.Now()
		p, err := box.Expose(context.Background(), 8080, tc.ask)
		after := time.Now()
		if err != nil {
			t.Fatal(err)
		}
		if p.ExpiresAt.Before(before.Add(tc.want).Truncate(time.Second)) || p.ExpiresAt.After(after.Add(tc.want)) {
			t.Errorf("ttl %s: expires %v, want about %s from now", tc.ask, p.ExpiresAt, tc.want)
		}
		if p.ExpiresAt.Location() != time.UTC {
			t.Errorf("ttl %s: expiry is in %s, want UTC", tc.ask, p.ExpiresAt.Location())
		}
	}
}

// A revoked credential is refused at once, before it expires.
func TestRevokeWithdrawsTheCredential(t *testing.T) {
	box, _ := previewSandboxes(t)
	p, err := box.Expose(context.Background(), 8080, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if err := box.Revoke(context.Background(), 8080, p.Token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if code := serve(box, p); code != http.StatusUnauthorized {
		t.Fatalf("revoked preview = %d, want 401", code)
	}
}

// One sandbox's caller must not be able to revoke another's previews, even
// though both share a handler.
func TestRevokeRefusesAnotherSandboxesCredential(t *testing.T) {
	box, other := previewSandboxes(t)
	theirs, err := other.Expose(context.Background(), 8080, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if err := box.Revoke(context.Background(), 8080, theirs.Token); !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("Revoke = %v, want ErrInvalid", err)
	}
	if code := serve(other, theirs); code != http.StatusBadGateway {
		t.Fatalf("their preview after a refused revoke = %d, want it still authorised", code)
	}
}
