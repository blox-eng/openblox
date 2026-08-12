package sandbox

import (
	"errors"
	"testing"
	"time"
)

func TestCommandValidate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     Command
		wantErr bool
	}{
		{"ok", Command{Argv: []string{"python3", "-c", "print(1)"}}, false},
		{"ok with env", Command{Argv: []string{"sh"}, Env: []string{"A=1"}}, false},
		{"empty value is valid env", Command{Argv: []string{"sh"}, Env: []string{"A="}}, false},
		{"no argv", Command{}, true},
		{"empty program", Command{Argv: []string{""}}, true},
		{"negative timeout", Command{Argv: []string{"sh"}, Timeout: -time.Second}, true},
		{"env without equals", Command{Argv: []string{"sh"}, Env: []string{"NOPE"}}, true},
		{"env with empty key", Command{Argv: []string{"sh"}, Env: []string{"=v"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v does not match ErrInvalid", err)
			}
		})
	}
}

// The security posture of the whole library rests on the zero-option case being
// the locked-down one. If this test ever needs updating, that is a deliberate
// change to the threat model, not a refactor.
func TestNewSpecDefaultsAreLockedDown(t *testing.T) {
	s := NewSpec()

	if s.Egress != EgressNone {
		t.Errorf("default egress = %v, want EgressNone", s.Egress)
	}
	if s.Runtime != DefaultRuntime {
		t.Errorf("default runtime = %q, want %q", s.Runtime, DefaultRuntime)
	}
	if s.User == "" || s.User == "root" || s.User == "0:0" {
		t.Errorf("default user = %q, want a non-root user", s.User)
	}
	if s.Resources.MaxProcesses <= 0 {
		t.Error("default MaxProcesses is unbounded; a fork bomb would exhaust host PIDs")
	}
	if s.Resources.CPUs <= 0 || s.Resources.MemoryBytes <= 0 || s.Resources.DiskBytes <= 0 {
		t.Errorf("default resources are unbounded: %+v", s.Resources)
	}
	if s.Lifetime.IdleTimeout <= 0 || s.Lifetime.MaxAge <= 0 {
		t.Errorf("default lifetime is unbounded: %+v", s.Lifetime)
	}
}

func TestWithResourcesKeepsUnsetDefaults(t *testing.T) {
	s := NewSpec(WithResources(Resources{MemoryBytes: 8 << 30}))

	if s.Resources.MemoryBytes != 8<<30 {
		t.Errorf("MemoryBytes = %d, want %d", s.Resources.MemoryBytes, int64(8<<30))
	}
	if s.Resources.CPUs != DefaultCPUs {
		t.Errorf("CPUs = %v, want default %v", s.Resources.CPUs, float64(DefaultCPUs))
	}
	if s.Resources.MaxProcesses != DefaultMaxProcesses {
		t.Errorf("MaxProcesses = %d, want default %d", s.Resources.MaxProcesses, DefaultMaxProcesses)
	}
}

func TestResolveTimeout(t *testing.T) {
	s := NewSpec(WithCommandTimeouts(30*time.Second, 5*time.Minute))

	tests := []struct {
		name      string
		requested time.Duration
		want      time.Duration
	}{
		{"unset uses default", 0, 30 * time.Second},
		{"negative uses default", -time.Second, 30 * time.Second},
		{"within bounds passes through", time.Minute, time.Minute},
		{"at maximum passes through", 5 * time.Minute, 5 * time.Minute},
		{"above maximum clamps", time.Hour, 5 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.ResolveTimeout(tt.requested); got != tt.want {
				t.Errorf("ResolveTimeout(%v) = %v, want %v", tt.requested, got, tt.want)
			}
		})
	}
}

func TestPreviewExpired(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	p := Preview{ExpiresAt: now.Add(time.Minute)}

	if p.Expired(now) {
		t.Error("preview expired before its deadline")
	}
	if !p.Expired(now.Add(time.Minute)) {
		t.Error("preview not expired exactly at its deadline; boundary must not grant access")
	}
	if !p.Expired(now.Add(2 * time.Minute)) {
		t.Error("preview not expired after its deadline")
	}
}

func TestWithLabelDoesNotAliasAcrossSpecs(t *testing.T) {
	opt := WithLabel("owner", "a")
	first, second := NewSpec(opt), NewSpec(opt)

	second.Labels["owner"] = "b"

	if first.Labels["owner"] != "a" {
		t.Errorf("first spec label = %q, want %q; option shares a map across specs", first.Labels["owner"], "a")
	}
}
