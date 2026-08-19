package brokerclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// TLSFiles is the client's half of the mTLS credential openbloxd verifies.
//
// It takes file paths rather than a *tls.Config deliberately. Exposing a
// *tls.Config would mean accepting InsecureSkipVerify and then refusing it at
// runtime; taking paths makes an unverified client inexpressible instead. If
// in-memory certificates are ever needed, that is an Option.
type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string

	// ServerName overrides the name verified against the daemon's
	// certificate. Leave it empty and it is derived from the dial address,
	// which is what you want unless you dial by IP and the certificate names
	// a host.
	ServerName string
}

// NewRemote returns a Client that dials openbloxd over the network.
//
// The credential is a positional argument rather than an Option because it is
// not optional: openbloxd requires a client certificate, and a Client built
// without one could only ever fail at the handshake.
func NewRemote(address string, files TLSFiles, opts ...Option) (*Client, error) {
	if address == "" {
		return nil, fmt.Errorf("%w: address is empty", sandbox.ErrInvalid)
	}
	cfg, err := files.config()
	if err != nil {
		return nil, err
	}
	return newClient(address, func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{Config: cfg}
		return d.DialContext(ctx, "tcp", address)
	}, opts...)
}

func (f TLSFiles) config() (*tls.Config, error) {
	if f.CertFile == "" || f.KeyFile == "" || f.CAFile == "" {
		return nil, fmt.Errorf("%w: cert, key and CA files are all required to reach openbloxd over a network", sandbox.ErrInvalid)
	}
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	caPEM, err := os.ReadFile(f.CAFile) //nolint:gosec // the caller's own configured path, not request input
	if err != nil {
		return nil, fmt.Errorf("read CA %q: %w", f.CAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: CA %q contains no certificate", sandbox.ErrInvalid, f.CAFile)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   f.ServerName,
	}, nil
}
