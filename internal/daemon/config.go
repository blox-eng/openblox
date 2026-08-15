// Package daemon implements openbloxd: the policy broker that owns the Docker
// connection so its callers need no socket access.
package daemon

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blox-eng/openblox/pkg/docker"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Config is the daemon's whole configuration.
type Config struct {
	Socket       string             `yaml:"socket"`
	SocketGroup  string             `yaml:"socket_group"`
	ReapInterval time.Duration      `yaml:"reap_interval"`
	Profiles     map[string]Profile `yaml:"profiles"`
}

// Profile is one named isolation policy. Every field here is deliberately
// unreachable from a request: this struct is the reason WithRuntime and
// WithEgress cannot be asked for over the wire.
type Profile struct {
	Image          string        `yaml:"image"`
	Runtime        string        `yaml:"runtime"`
	Egress         string        `yaml:"egress"`
	User           string        `yaml:"user"`
	CPUs           float64       `yaml:"cpus"`
	MemoryMB       int64         `yaml:"memory_mb"`
	DiskMB         int64         `yaml:"disk_mb"`
	MaxProcesses   int           `yaml:"max_processes"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxAge         time.Duration `yaml:"max_age"`
	DefaultTimeout time.Duration `yaml:"default_timeout"`
	MaxTimeout     time.Duration `yaml:"max_timeout"`
	RegistryAuth   *RegistryAuth `yaml:"registry_auth"`
}

// RegistryAuth authenticates image pulls. It lives here, and only here: the
// credentials never leave the daemon and are never a request field.
type RegistryAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Load reads and validates a config file.
//
// Decoding is strict. A misspelled key is a refusal to start rather than a
// silently unapplied bound, because an unapplied bound looks identical to a
// working one until something escapes.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Socket == "" {
		return fmt.Errorf("%w: socket path is empty", sandbox.ErrInvalid)
	}
	if len(c.Profiles) == 0 {
		return fmt.Errorf("%w: no profiles configured; the daemon would accept nothing", sandbox.ErrInvalid)
	}
	if c.ReapInterval == 0 {
		c.ReapInterval = time.Minute
	}
	var authName string
	var auth *RegistryAuth
	for name, p := range c.Profiles {
		if err := p.validate(name); err != nil {
			return err
		}
		if p.RegistryAuth == nil {
			continue
		}
		if auth == nil {
			authName, auth = name, p.RegistryAuth
		} else if *p.RegistryAuth != *auth {
			// docker.Option configures the Backend, not a single pull: one Docker
			// connection carries one credential. Map iteration order is random, so
			// silently picking a "last one wins" credential would mean the daemon
			// authenticates as a different registry account on every restart.
			// Refuse rather than serve with an operator-invisible coin flip.
			return fmt.Errorf("%w: profiles %q and %q specify different registry_auth, but one Docker connection carries one credential",
				sandbox.ErrInvalid, authName, name)
		}
	}
	return nil
}

// validate rejects a profile whose bounds cannot mean what they look like
// they mean.
//
// A zero-valued bound here is not "unlimited" — it is "inherit the library's
// conservative default". Options() feeds every field through WithResources
// and WithLifetime, and both ignore a zero field rather than clearing it (see
// pkg/sandbox/options.go), so a profile that omits idle_timeout and max_age
// entirely — the reference config's "browser" profile does exactly this —
// still ends up bounded by sandbox.DefaultIdleTimeout and
// sandbox.DefaultMaxAge, not unbounded. That is what makes it safe to leave a
// bound out of a profile at all.
func (p Profile) validate(name string) error {
	if p.Image == "" {
		return fmt.Errorf("%w: profile %q has no image", sandbox.ErrInvalid, name)
	}
	switch p.Egress {
	case "", "none", "unrestricted":
	default:
		return fmt.Errorf("%w: profile %q has egress %q, want none or unrestricted", sandbox.ErrInvalid, name, p.Egress)
	}
	// Negative durations and negative resources fail for different reasons.
	// WithLifetime treats a negative value as "disable this bound" by
	// documented design (pkg/sandbox/options.go), so idle_timeout: -1s in a
	// profile would silently turn off reaping for it — a real footgun, not a
	// typo that resolves safely. WithResources instead ignores any
	// non-positive field and falls back to the library default, so
	// memory_mb: -1 cannot weaken isolation on its own; it is rejected here
	// only so an operator's typo is loud rather than quietly overridden.
	if p.CPUs < 0 {
		return fmt.Errorf("%w: profile %q has negative cpus %v", sandbox.ErrInvalid, name, p.CPUs)
	}
	if p.MemoryMB < 0 {
		return fmt.Errorf("%w: profile %q has negative memory_mb %d", sandbox.ErrInvalid, name, p.MemoryMB)
	}
	if p.DiskMB < 0 {
		return fmt.Errorf("%w: profile %q has negative disk_mb %d", sandbox.ErrInvalid, name, p.DiskMB)
	}
	if p.MaxProcesses < 0 {
		return fmt.Errorf("%w: profile %q has negative max_processes %d", sandbox.ErrInvalid, name, p.MaxProcesses)
	}
	if p.IdleTimeout < 0 {
		return fmt.Errorf("%w: profile %q has negative idle_timeout %s, which silently disables reaping", sandbox.ErrInvalid, name, p.IdleTimeout)
	}
	if p.MaxAge < 0 {
		return fmt.Errorf("%w: profile %q has negative max_age %s, which silently disables reaping", sandbox.ErrInvalid, name, p.MaxAge)
	}
	if p.DefaultTimeout < 0 {
		return fmt.Errorf("%w: profile %q has negative default_timeout %s", sandbox.ErrInvalid, name, p.DefaultTimeout)
	}
	if p.MaxTimeout < 0 {
		return fmt.Errorf("%w: profile %q has negative max_timeout %s", sandbox.ErrInvalid, name, p.MaxTimeout)
	}
	if err := sandbox.NewSpec(p.Options()...).Resources.Validate(); err != nil {
		return fmt.Errorf("profile %q: %w", name, err)
	}
	return nil
}

// DigestPinned reports whether the profile's image is pinned by digest. The
// daemon warns rather than refuses: refusing would make a local tag-built image
// unusable in development, where there is no registry to pin against.
func (p Profile) DigestPinned() bool { return docker.IsDigestPinned(p.Image) }

// Options renders the profile as library options.
//
// This function is the only place in openbloxd that produces WithRuntime or
// WithEgress, and its sole input is the config file. Nothing derived from a
// request reaches it. Keep it that way.
func (p Profile) Options() []sandbox.CreateOption {
	opts := []sandbox.CreateOption{
		sandbox.WithImage(p.Image),
		sandbox.WithResources(sandbox.Resources{
			CPUs:         p.CPUs,
			MemoryBytes:  p.MemoryMB << 20,
			DiskBytes:    p.DiskMB << 20,
			MaxProcesses: p.MaxProcesses,
		}),
		sandbox.WithLifetime(sandbox.Lifetime{
			IdleTimeout: p.IdleTimeout,
			MaxAge:      p.MaxAge,
		}),
		sandbox.WithCommandTimeouts(p.DefaultTimeout, p.MaxTimeout),
	}
	if p.Runtime != "" {
		opts = append(opts, sandbox.WithRuntime(p.Runtime))
	}
	if p.User != "" {
		opts = append(opts, sandbox.WithUser(p.User))
	}
	if p.Egress == "unrestricted" {
		opts = append(opts, sandbox.WithEgress(sandbox.EgressUnrestricted))
	}
	return opts
}
