package brokerclient

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/internal/testpki"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

func TestNewRemoteRequiresAnAddress(t *testing.T) {
	_, err := NewRemote("", TLSFiles{CertFile: "/c", KeyFile: "/k", CAFile: "/ca"})
	if !errors.Is(err, sandbox.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

// The credential is not optional and cannot be defaulted away: a client that
// presented nothing would be talking to a daemon that must reject it, and the
// clearer failure is here.
func TestNewRemoteRequiresEveryCredentialFile(t *testing.T) {
	cases := map[string]TLSFiles{
		"no cert": {KeyFile: "/k", CAFile: "/ca"},
		"no key":  {CertFile: "/c", CAFile: "/ca"},
		"no ca":   {CertFile: "/c", KeyFile: "/k"},
		"none":    {},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewRemote("127.0.0.1:9443", files)
			if !errors.Is(err, sandbox.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNewRemoteReportsAnUnreadableCredential(t *testing.T) {
	_, err := NewRemote("127.0.0.1:9443", TLSFiles{
		CertFile: "/nonexistent/c", KeyFile: "/nonexistent/k", CAFile: "/nonexistent/ca",
	})
	if err == nil {
		t.Fatal("NewRemote succeeded with unreadable credential files")
	}
	if !strings.Contains(err.Error(), "keypair") {
		t.Errorf("error = %v, want it to name the keypair", err)
	}
}

// New keeps its exact signature and behaviour: a same-host caller is untouched
// by any of this.
func TestNewStillTakesOnlyASocketPath(t *testing.T) {
	c, err := New("/run/openbloxd/openbloxd.sock")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.target != "/run/openbloxd/openbloxd.sock" {
		t.Errorf("target = %q, want the socket path", c.target)
	}
	if c.dial == nil {
		t.Error("dial is nil; New must install a dialler")
	}
}

// newPKI builds a throwaway authority plus a client keypair on disk, and
// returns the TLSFiles a Client is constructed from.
func newPKI(t *testing.T) (*testpki.PKI, TLSFiles) {
	t.Helper()
	p, err := testpki.New(t.TempDir())
	if err != nil {
		t.Fatalf("testpki.New: %v", err)
	}
	certFile, keyFile, err := p.WriteClient("sandbox-caller")
	if err != nil {
		t.Fatalf("WriteClient: %v", err)
	}
	return p, TLSFiles{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   p.CAFile,
		// The daemon's certificate names "openbloxd", but the test dials
		// 127.0.0.1 — so the name to verify has to be given explicitly. This
		// is exactly the case ServerName exists for.
		ServerName: "openbloxd",
	}
}

// listen starts a TLS listener that requires a client certificate from p.
func listen(t *testing.T, p *testpki.PKI) net.Listener {
	t.Helper()
	cfg, err := p.ServerTLS()
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return tls.NewListener(ln, cfg)
}
