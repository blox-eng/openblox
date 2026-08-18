package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// ListenTLS creates the network listener the daemon serves on.
//
// Two gates, both during the handshake. The client certificate must chain to
// the configured CA, and its Common Name must be on the allowlist.
//
// The second gate is not belt-and-braces. With verification alone the CA is
// the whole access control list, so a CA shared with anything else silently
// grants sandbox creation to whatever that other thing issued. The allowlist
// is what makes a CA mis-issuance survivable, and what makes the set of
// permitted callers something an operator can read in one place.
//
// Rejecting during the handshake rather than in a middleware means a caller
// that fails either gate never reaches the request router at all.
func ListenTLS(cfg ListenConfig) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.TLS.ClientCAFile) //nolint:gosec // the operator's own config path, not request input
	if err != nil {
		return nil, fmt.Errorf("read client CA %q: %w", cfg.TLS.ClientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: client CA %q contains no certificate", sandbox.ErrInvalid, cfg.TLS.ClientCAFile)
	}

	allowed := make(map[string]struct{}, len(cfg.TLS.AllowedClientCNs))
	for _, cn := range cfg.TLS.AllowedClientCNs {
		allowed[cn] = struct{}{}
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			// RequireAndVerifyClientCert has already built and verified a
			// chain by the time this runs, so chains[0][0] is the leaf.
			cn := chains[0][0].Subject.CommonName
			if _, ok := allowed[cn]; !ok {
				// Logged because the client only sees a TLS alert, and an
				// operator debugging a rejected caller has nothing else to
				// go on.
				slog.Warn("rejected client certificate: common name is not allowed",
					slog.String("common_name", cn))
				return fmt.Errorf("client certificate common name %q is not allowed", cn)
			}
			return nil
		},
	}

	ln, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", cfg.Address, err)
	}
	return tls.NewListener(ln, tlsCfg), nil
}
