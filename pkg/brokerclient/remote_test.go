package brokerclient

import (
	"errors"
	"strings"
	"testing"

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
