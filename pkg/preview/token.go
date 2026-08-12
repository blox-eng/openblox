// Package preview issues and validates short-lived credentials for reaching a
// port inside a sandbox, and serves the reverse proxy that carries the traffic.
//
// Tokens are self-describing and signed, so validating one is a local HMAC
// computation. Nothing is looked up, so the proxy needs no database and no
// control plane to call — which is the whole reason openblox can be a library
// rather than a service.
package preview

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidToken is returned for a token that is malformed, misapplied,
// expired, or not signed by this signer. It is deliberately one error: telling a
// caller which of those it was tells an attacker the same thing.
var ErrInvalidToken = errors.New("invalid preview token")

// MinKeyBytes is the shortest accepted signing key. Below a full HMAC-SHA256
// block of entropy the signature is the weakest link in the whole scheme.
const MinKeyBytes = 32

// MaxTTL bounds how long a preview credential may live. A preview is a way to
// look at something now, not a way to publish it.
const MaxTTL = 24 * time.Hour

// tokenVersion prefixes every token so the format can change without silently
// accepting old tokens under new rules.
const tokenVersion = "ob1"

// domainSeparator keeps this signature from ever validating in another context
// that happens to use the same key.
const domainSeparator = "openblox-preview-v1"

// nonceBytes makes each token unique, so that revoking one issued for a sandbox
// and port does not revoke another issued for the same pair.
const nonceBytes = 16

// Signer mints and verifies preview tokens. It is safe for concurrent use, and
// several processes sharing a key produce and accept each other's tokens.
type Signer struct {
	key []byte
}

// NewSigner returns a Signer over key, which must be at least MinKeyBytes long
// and should come from a CSPRNG. The same key must be configured everywhere
// tokens are minted or checked.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < MinKeyBytes {
		return nil, fmt.Errorf("preview signing key is %d bytes, need at least %d", len(key), MinKeyBytes)
	}
	return &Signer{key: append([]byte(nil), key...)}, nil
}

// Sign returns a bearer credential for a port in a sandbox, valid until
// expiresAt.
//
// The result is a secret. Send it in an Authorization header and nowhere else:
// a credential in a query string is copied into access logs, browser history,
// bookmarks, and the Referer header of every outbound link the page makes.
func (s *Signer) Sign(sandboxName string, port int, expiresAt time.Time) (string, error) {
	if sandboxName == "" {
		return "", errors.New("preview token needs a sandbox name")
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("preview port %d is out of range", port)
	}

	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate preview nonce: %w", err)
	}

	payload := fmt.Sprintf("%d:%d:%s", port, expiresAt.UTC().UnixNano(), encode(nonce))
	return tokenVersion + "." + payload + "." + encode(s.mac(sandboxName, payload)), nil
}

// Verify reports whether token authorises this sandbox and port as of now.
//
// The sandbox name and port come from the route being served, not from the
// token, so a token minted for one sandbox cannot be replayed against another.
func (s *Signer) Verify(token, sandboxName string, port int, now time.Time) error {
	version, payload, mac, ok := split(token)
	if !ok || version != tokenVersion {
		return ErrInvalidToken
	}

	// Authenticate before parsing anything out of the payload: unsigned input
	// should never reach a parser, let alone influence a decision.
	if !hmac.Equal(mac, s.mac(sandboxName, payload)) {
		return ErrInvalidToken
	}

	tokenPort, expiresAt, err := parsePayload(payload)
	if err != nil {
		return ErrInvalidToken
	}
	if tokenPort != port {
		return ErrInvalidToken
	}
	if !now.Before(expiresAt) {
		return ErrInvalidToken
	}
	return nil
}

// ExpiresAt reports when token stops being valid. It does not authenticate the
// token; callers use it only after Verify, to expire cached bookkeeping.
func ExpiresAt(token string) (time.Time, bool) {
	_, payload, _, ok := split(token)
	if !ok {
		return time.Time{}, false
	}
	_, expiresAt, err := parsePayload(payload)
	if err != nil {
		return time.Time{}, false
	}
	return expiresAt, true
}

// ClampTTL bounds a requested lifetime to something a preview should have.
func ClampTTL(ttl, fallback time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = fallback
	}
	if ttl > MaxTTL {
		return MaxTTL
	}
	return ttl
}

func (s *Signer) mac(sandboxName, payload string) []byte {
	h := hmac.New(sha256.New, s.key)
	// Length-prefix-free fields are separated by a byte that cannot appear in
	// them, so no two different inputs can produce the same signed string.
	for _, part := range []string{domainSeparator, sandboxName, payload} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

func split(token string) (version, payload string, mac []byte, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", nil, false
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", nil, false
	}
	return parts[0], parts[1], mac, true
}

func parsePayload(payload string) (port int, expiresAt time.Time, err error) {
	fields := strings.Split(payload, ":")
	if len(fields) != 3 {
		return 0, time.Time{}, ErrInvalidToken
	}
	port, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, time.Time{}, ErrInvalidToken
	}
	nanos, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, time.Time{}, ErrInvalidToken
	}
	return port, time.Unix(0, nanos).UTC(), nil
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
