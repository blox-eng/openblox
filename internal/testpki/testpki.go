// Package testpki generates a throwaway certificate authority for tests that
// need a real mTLS handshake.
//
// It is a normal package rather than a _test.go file because two packages
// need it, and it deliberately imports neither testing nor internal/daemon —
// the former would leak test flags into anything linking it, the latter would
// be an import cycle with the daemon's in-package tests.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PKI is a certificate authority plus a server keypair signed by it, written
// to a temporary directory. A test needing a second, untrusted authority just
// calls New again.
type PKI struct {
	Dir      string
	CAFile   string
	CertFile string
	KeyFile  string

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// New returns a PKI whose files are written under dir. Pass t.TempDir().
func New(dir string) (*PKI, error) {
	caCert, caKey, err := issueCA()
	if err != nil {
		return nil, err
	}
	p := &PKI{
		Dir:      dir,
		CAFile:   filepath.Join(dir, "ca.crt"),
		CertFile: filepath.Join(dir, "server.crt"),
		KeyFile:  filepath.Join(dir, "server.key"),
		caCert:   caCert,
		caKey:    caKey,
	}
	if err := writePEM(p.CAFile, "CERTIFICATE", caCert.Raw); err != nil {
		return nil, err
	}

	der, key, err := p.issue("openbloxd", true)
	if err != nil {
		return nil, err
	}
	if err := writePEM(p.CertFile, "CERTIFICATE", der); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(p.KeyFile, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}
	return p, nil
}

// Pool is this authority's certificate, for verifying the server leg.
func (p *PKI) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	return pool
}

// ClientTLS returns a client config presenting a certificate with the given
// Common Name and trusting this authority.
func (p *PKI) ClientTLS(cn string) (*tls.Config, error) {
	der, key, err := p.issue(cn, false)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		RootCAs:      p.Pool(),
		ServerName:   "openbloxd",
	}, nil
}

// WriteClient writes a client keypair for cn and returns its cert and key
// paths, for a caller configured by file rather than by tls.Config.
func (p *PKI) WriteClient(cn string) (certFile, keyFile string, err error) {
	der, key, err := p.issue(cn, false)
	if err != nil {
		return "", "", err
	}
	certFile = filepath.Join(p.Dir, cn+".crt")
	keyFile = filepath.Join(p.Dir, cn+".key")
	if err := writePEM(certFile, "CERTIFICATE", der); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// ServerTLS is the daemon-side config a test listener needs: this authority's
// keypair, requiring and verifying a client certificate from it.
//
// It deliberately carries no common-name allowlist — it exists to stand up a
// plain TLS listener for transport-level tests, not to exercise access
// control. It is not a substitute for ListenTLS: anything asserting on
// allowlist behaviour must use ListenTLS.
func (p *PKI) ServerTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.Pool(),
	}, nil
}

func (p *PKI) issue(cn string, server bool) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"openbloxd", "localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func issueCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "testpki-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func writePEM(path, blockType string, der []byte) error {
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
