package sandbox

import "time"

// EgressPolicy controls a sandbox's outbound network access.
type EgressPolicy int

const (
	// EgressNone gives the sandbox no network interface at all. It is the zero
	// value, and therefore the default.
	//
	// This is stronger than a firewall that drops outbound packets: with no
	// interface there is no DNS resolver to abuse as a covert channel, and no
	// route to host-local metadata services. Files still move in and out over
	// the runtime's control channel, so default-deny costs nothing functionally.
	EgressNone EgressPolicy = iota

	// EgressUnrestricted gives the sandbox ordinary host networking.
	//
	// Only appropriate when the code being run is trusted. If it is trusted, ask
	// why it needs a sandbox.
	EgressUnrestricted
)

// Resources bounds what a single sandbox may consume.
type Resources struct {
	CPUs        float64
	MemoryBytes int64

	// DiskBytes caps the sandbox's writable scratch space.
	//
	// The root filesystem is read-only, so all writes land on sized tmpfs mounts
	// and this is their combined ceiling. Container-layer quotas
	// (--storage-opt size) are deliberately not used: they require overlay2 on
	// xfs with pquota and hard-fail on the far more common ext4, so relying on
	// them would make the disk bound silently unavailable on most hosts.
	//
	// Because tmpfs is RAM-backed, this budget is drawn from MemoryBytes rather
	// than being independent of it: a sandbox that fills its scratch space has
	// that much less memory for processes. DiskBytes must not exceed
	// MemoryBytes.
	DiskBytes int64

	// MaxProcesses caps the process count. Without it a fork bomb inside the
	// sandbox exhausts host PIDs regardless of CPU and memory limits.
	MaxProcesses int
}

// Validate reports whether the bounds are internally consistent.
func (r Resources) Validate() error {
	if r.DiskBytes > r.MemoryBytes {
		return newInvalidError(
			"DiskBytes (%d) exceeds MemoryBytes (%d): scratch space is tmpfs and is drawn from the memory budget",
			r.DiskBytes, r.MemoryBytes)
	}
	return nil
}

// Lifetime bounds how long a sandbox may live.
type Lifetime struct {
	// IdleTimeout stops a sandbox with no activity for this long.
	IdleTimeout time.Duration
	// MaxAge destroys a sandbox this long after creation regardless of activity.
	// It reaps what the idle sweep misses — a sandbox kept warm by a wedged
	// background process is never idle.
	MaxAge time.Duration
}

// Spec is the resolved configuration for a new sandbox. Callers build one
// through [CreateOption] values rather than constructing it directly.
type Spec struct {
	Image     string
	Runtime   string
	User      string
	Resources Resources
	Lifetime  Lifetime
	Egress    EgressPolicy
	Env       []string
	Labels    map[string]string

	// DefaultTimeout applies to commands that set none.
	DefaultTimeout time.Duration
	// MaxTimeout is the ceiling a command may request.
	MaxTimeout time.Duration
}

// Defaults for a sandbox created with no options. Conservative on purpose:
// raising a limit is a visible edit at the call site, and a caller who forgets
// an option gets the restrictive behaviour rather than the permissive one.
const (
	DefaultRuntime     = "runsc"
	DefaultUser        = "1000:1000"
	DefaultCPUs        = 2
	DefaultMemoryBytes = 2 << 30 // 2 GiB
	// DefaultDiskBytes is scratch space, drawn from the memory budget because it
	// is tmpfs. Half of memory leaves room for the processes doing the writing.
	DefaultDiskBytes      = 1 << 30 // 1 GiB
	DefaultMaxProcesses   = 256
	DefaultIdleTimeout    = 15 * time.Minute
	DefaultMaxAge         = 2 * time.Hour
	DefaultCommandTimeout = 60 * time.Second
	// MaxCommandTimeout bounds what a caller may request. Long enough for heavy
	// domain compute (large-model geometry, big spreadsheet parses) without
	// letting a wedged call hold a slot indefinitely.
	MaxCommandTimeout = 10 * time.Minute
)

// NewSpec resolves options over the secure defaults.
func NewSpec(opts ...CreateOption) Spec {
	s := Spec{
		Runtime: DefaultRuntime,
		User:    DefaultUser,
		Resources: Resources{
			CPUs:         DefaultCPUs,
			MemoryBytes:  DefaultMemoryBytes,
			DiskBytes:    DefaultDiskBytes,
			MaxProcesses: DefaultMaxProcesses,
		},
		Lifetime: Lifetime{
			IdleTimeout: DefaultIdleTimeout,
			MaxAge:      DefaultMaxAge,
		},
		Egress:         EgressNone,
		DefaultTimeout: DefaultCommandTimeout,
		MaxTimeout:     MaxCommandTimeout,
	}
	for _, opt := range opts {
		opt(&s)
	}
	return s
}

// ResolveTimeout returns the effective timeout for a requested duration,
// substituting the default when unset and clamping to the maximum.
func (s Spec) ResolveTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		requested = s.DefaultTimeout
	}
	if s.MaxTimeout > 0 && requested > s.MaxTimeout {
		return s.MaxTimeout
	}
	return requested
}

// CreateOption customises a sandbox at creation.
type CreateOption func(*Spec)

// WithImage sets the container image. Pin a digest rather than a tag: a tag can
// be repointed under you, and the image is the sandbox's entire userland.
func WithImage(ref string) CreateOption {
	return func(s *Spec) { s.Image = ref }
}

// WithRuntime overrides the isolation runtime. The default, runsc, is gVisor.
// Setting this to the host's default runtime trades away the isolation openblox
// exists to provide.
func WithRuntime(name string) CreateOption {
	return func(s *Spec) { s.Runtime = name }
}

// WithUser sets the uid:gid the sandbox runs as. It must not be root.
func WithUser(user string) CreateOption {
	return func(s *Spec) { s.User = user }
}

// WithResources overrides the resource bounds. Zero-valued fields keep their
// defaults, so a caller can raise memory alone without unbounding the rest.
func WithResources(r Resources) CreateOption {
	return func(s *Spec) {
		if r.CPUs > 0 {
			s.Resources.CPUs = r.CPUs
		}
		if r.MemoryBytes > 0 {
			s.Resources.MemoryBytes = r.MemoryBytes
		}
		if r.DiskBytes > 0 {
			s.Resources.DiskBytes = r.DiskBytes
		}
		if r.MaxProcesses > 0 {
			s.Resources.MaxProcesses = r.MaxProcesses
		}
	}
}

// WithLifetime overrides the idle and max-age bounds. A zero field keeps its
// default; use a negative value to disable a bound entirely.
func WithLifetime(l Lifetime) CreateOption {
	return func(s *Spec) {
		if l.IdleTimeout != 0 {
			s.Lifetime.IdleTimeout = l.IdleTimeout
		}
		if l.MaxAge != 0 {
			s.Lifetime.MaxAge = l.MaxAge
		}
	}
}

// WithEgress relaxes the default of no network access.
func WithEgress(p EgressPolicy) CreateOption {
	return func(s *Spec) { s.Egress = p }
}

// WithEnv appends environment entries, each "KEY=value".
func WithEnv(entries ...string) CreateOption {
	return func(s *Spec) { s.Env = append(s.Env, entries...) }
}

// WithLabel attaches a label for the caller's own bookkeeping. Labels are
// visible to host tooling and must not carry secrets.
func WithLabel(key, value string) CreateOption {
	return func(s *Spec) {
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		s.Labels[key] = value
	}
}

// WithCommandTimeouts overrides the default and maximum command durations.
func WithCommandTimeouts(def, ceiling time.Duration) CreateOption {
	return func(s *Spec) {
		if def > 0 {
			s.DefaultTimeout = def
		}
		if ceiling > 0 {
			s.MaxTimeout = ceiling
		}
	}
}
