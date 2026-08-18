// Package daemon implements openbloxd: the policy broker that owns the Docker
// connection so its callers need no socket access.
package daemon

import (
	"fmt"
	"net"
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
	Listen       *ListenConfig      `yaml:"listen"`
	ReapInterval time.Duration      `yaml:"reap_interval"`
	Profiles     map[string]Profile `yaml:"profiles"`
}

// ListenConfig is the network listener. Absent means the daemon serves only
// its Unix socket, which stays the default and the recommended arrangement
// wherever caller and daemon share a host.
type ListenConfig struct {
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
}

// TLSConfig is the daemon's half of the mTLS credential, plus the allowlist
// that stops the CA from being the whole access control list.
type TLSConfig struct {
	CertFile         string   `yaml:"cert_file"`
	KeyFile          string   `yaml:"key_file"`
	ClientCAFile     string   `yaml:"client_ca_file"`
	AllowedClientCNs []string `yaml:"allowed_client_cns"`
}

// IsWildcardHost reports whether the address binds every interface. That is a
// legitimate choice for a daemon whose network namespace is already the
// boundary, and a serious mistake otherwise — so it is warned about at boot
// rather than refused.
func (l ListenConfig) IsWildcardHost() bool {
	host, _, err := net.SplitHostPort(l.Address)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
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
	MaxSandboxes   int           `yaml:"max_sandboxes"`
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
	f, err := os.Open(path) //nolint:gosec // path is the operator's own --config flag, not request input; whoever can set it can already read the file directly
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
	// The socket may be omitted only when a network listener replaces it.
	// Neither one set is a daemon that starts, binds nothing and answers
	// nothing — indistinguishable from a working one until a caller times out.
	if c.Socket == "" && c.Listen == nil {
		return fmt.Errorf("%w: neither socket nor listen is set; the daemon would accept nothing", sandbox.ErrInvalid)
	}
	if c.Listen != nil {
		if err := c.Listen.validate(); err != nil {
			return err
		}
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

// validate refuses a listen block that is not completely specified.
//
// Nothing here defaults. A daemon that starts listening on a network interface
// because a key was omitted is the failure this block exists to avoid, and a
// listener that accepted any certificate its CA ever signed would make the CA
// the entire access control list.
func (l *ListenConfig) validate() error {
	if l.Address == "" {
		return fmt.Errorf("%w: listen.address is empty; a bind address has no default", sandbox.ErrInvalid)
	}
	if _, _, err := net.SplitHostPort(l.Address); err != nil {
		return fmt.Errorf("%w: listen.address %q is not host:port: %s", sandbox.ErrInvalid, l.Address, err)
	}
	switch {
	case l.TLS.CertFile == "":
		return fmt.Errorf("%w: listen.tls.cert_file is empty", sandbox.ErrInvalid)
	case l.TLS.KeyFile == "":
		return fmt.Errorf("%w: listen.tls.key_file is empty", sandbox.ErrInvalid)
	case l.TLS.ClientCAFile == "":
		return fmt.Errorf("%w: listen.tls.client_ca_file is empty; without it any client certificate would be accepted", sandbox.ErrInvalid)
	case len(l.TLS.AllowedClientCNs) == 0:
		return fmt.Errorf("%w: listen.tls.allowed_client_cns is empty; the CA alone must not be the access control list", sandbox.ErrInvalid)
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
	// Zero means unlimited, which is what an unset cap has always meant. A
	// negative value would read the same way while being a typo, and "the cap
	// silently did not apply" is the one outcome this setting exists to prevent.
	if p.MaxSandboxes < 0 {
		return fmt.Errorf("%w: profile %q has negative max_sandboxes %d; omit it for unlimited", sandbox.ErrInvalid, name, p.MaxSandboxes)
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
	// Each bound is sane on its own but nonsense together: a default above the
	// maximum means every exec is clamped below the default the operator
	// configured, so the profile never once does what it says.
	if p.MaxTimeout > 0 && p.DefaultTimeout > p.MaxTimeout {
		return fmt.Errorf("%w: profile %q has default_timeout %s above max_timeout %s, so every command is clamped below its own default",
			sandbox.ErrInvalid, name, p.DefaultTimeout, p.MaxTimeout)
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
