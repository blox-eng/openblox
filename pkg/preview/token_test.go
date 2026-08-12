package preview

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(bytes.Repeat([]byte("k"), MinKeyBytes))
	if err != nil {
		t.Fatalf("NewSigner = %v", err)
	}
	return s
}

func TestNewSignerRejectsAShortKey(t *testing.T) {
	if _, err := NewSigner(bytes.Repeat([]byte("k"), MinKeyBytes-1)); err == nil {
		t.Error("accepted a key shorter than a full HMAC block")
	}
}

func TestSignedTokenVerifies(t *testing.T) {
	s := testSigner(t)
	now := time.Now()

	token, err := s.Sign("session-a", 3000, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	if err := s.Verify(token, "session-a", 3000, now); err != nil {
		t.Errorf("Verify = %v, want nil", err)
	}
}

// A token is scoped to exactly one sandbox and one port. Anything looser and a
// caller holding one preview holds them all.
func TestTokenIsBoundToItsSandboxAndPort(t *testing.T) {
	s := testSigner(t)
	now := time.Now()

	token, err := s.Sign("session-a", 3000, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	if err := s.Verify(token, "session-b", 3000, now); !errors.Is(err, ErrInvalidToken) {
		t.Error("a token minted for session-a validated against session-b")
	}
	if err := s.Verify(token, "session-a", 3001, now); !errors.Is(err, ErrInvalidToken) {
		t.Error("a token minted for port 3000 validated against port 3001")
	}
}

func TestExpiredTokenIsRefused(t *testing.T) {
	s := testSigner(t)
	now := time.Now()

	token, err := s.Sign("session-a", 3000, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	if err := s.Verify(token, "session-a", 3000, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidToken) {
		t.Error("an expired token still validated")
	}
	// The boundary is exclusive: a token is dead at its expiry, not after it.
	if err := s.Verify(token, "session-a", 3000, now.Add(time.Second)); !errors.Is(err, ErrInvalidToken) {
		t.Error("a token validated at exactly its expiry")
	}
}

func TestTokenFromAnotherKeyIsRefused(t *testing.T) {
	mine := testSigner(t)
	theirs, err := NewSigner(bytes.Repeat([]byte("x"), MinKeyBytes))
	if err != nil {
		t.Fatalf("NewSigner = %v", err)
	}
	now := time.Now()

	token, err := theirs.Sign("session-a", 3000, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	if err := mine.Verify(token, "session-a", 3000, now); !errors.Is(err, ErrInvalidToken) {
		t.Error("a token signed with a different key validated")
	}
}

// The payload is attacker-controlled until the signature is checked, so no
// tampering with it may be accepted — including tampering that would otherwise
// grant a longer life or a different port.
func TestTamperedTokenIsRefused(t *testing.T) {
	s := testSigner(t)
	now := time.Now()

	token, err := s.Sign("session-a", 3000, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	parts := strings.Split(token, ".")

	forged := map[string]string{
		"extended expiry": parts[0] + ".3000:99999999999999999:AAAA." + parts[2],
		"different port":  parts[0] + ".3001:" + strings.SplitN(parts[1], ":", 2)[1] + "." + parts[2],
		"stripped mac":    parts[0] + "." + parts[1] + ".",
		"empty":           "",
		"no separators":   "garbage",
		"wrong version":   "ob2." + parts[1] + "." + parts[2],
		"swapped fields":  parts[0] + "." + parts[2] + "." + parts[1],
	}
	for name, bad := range forged {
		if err := s.Verify(bad, "session-a", 3000, now); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: Verify = %v, want ErrInvalidToken", name, err)
		}
	}
}

// Two tokens for the same sandbox and port must differ, or revoking one would
// revoke the other.
func TestTokensAreUnique(t *testing.T) {
	s := testSigner(t)
	expiry := time.Now().Add(time.Hour)

	first, err := s.Sign("session-a", 3000, expiry)
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	second, err := s.Sign("session-a", 3000, expiry)
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	if first == second {
		t.Error("two tokens for the same sandbox and port are identical")
	}
}

func TestSignRejectsUnusableInput(t *testing.T) {
	s := testSigner(t)
	expiry := time.Now().Add(time.Hour)

	if _, err := s.Sign("", 3000, expiry); err == nil {
		t.Error("signed a token with no sandbox name")
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := s.Sign("session-a", port, expiry); err == nil {
			t.Errorf("signed a token for port %d", port)
		}
	}
}

func TestClampTTLBoundsPreviewLifetime(t *testing.T) {
	const fallback = 10 * time.Minute

	if got := ClampTTL(0, fallback); got != fallback {
		t.Errorf("ClampTTL(0) = %v, want the fallback %v", got, fallback)
	}
	if got := ClampTTL(-time.Hour, fallback); got != fallback {
		t.Errorf("ClampTTL(negative) = %v, want the fallback %v", got, fallback)
	}
	if got := ClampTTL(time.Hour, fallback); got != time.Hour {
		t.Errorf("ClampTTL(1h) = %v, want 1h", got)
	}
	if got := ClampTTL(30*24*time.Hour, fallback); got != MaxTTL {
		t.Errorf("ClampTTL(30d) = %v, want it clamped to %v", got, MaxTTL)
	}
}

func TestExpiresAtReadsTheDeadline(t *testing.T) {
	s := testSigner(t)
	want := time.Now().Add(time.Hour).UTC().Truncate(time.Nanosecond)

	token, err := s.Sign("session-a", 3000, want)
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}
	got, ok := ExpiresAt(token)
	if !ok {
		t.Fatal("ExpiresAt could not read a token this package minted")
	}
	if !got.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got, want)
	}
	if _, ok := ExpiresAt("garbage"); ok {
		t.Error("ExpiresAt accepted a malformed token")
	}
}
