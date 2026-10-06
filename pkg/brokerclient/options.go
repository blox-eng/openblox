// Package brokerclient reaches openbloxd over a Unix socket or a mutual-TLS
// network connection.
//
// Its Client satisfies sandbox.Backend and its handle satisfies
// sandbox.Sandbox, so a caller swaps one constructor and stops needing
// Docker socket access.
package brokerclient

import (
	"fmt"
	"time"

	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// profileLabel carries the chosen profile from a CreateOption to Create. It
// travels as a label because CreateOption can only write to a Spec, and is
// stripped before the request is sent.
const profileLabel = "brokerclient.profile"

// WithProfile selects which of the daemon's configured profiles to create
// under. It is the only policy choice a caller has, and the daemon rejects a
// name it does not know.
func WithProfile(name string) sandbox.CreateOption {
	return sandbox.WithLabel(profileLabel, name)
}

// Option configures a Client.
type Option func(*Client) error

// WithPreviews enables Expose, signing credentials with key and serving them
// under baseURL — the same option the Docker backend takes.
//
// Minting a preview touches Docker nowhere: it signs a name, a port and an
// expiry. So it happens here, and the signing key lives in the one process
// that also verifies it. The daemon holds no key.
//
// This also builds the Handler that PreviewHandler returns, exactly as
// docker.WithPreviews builds one onto the Backend. Revoke calls into that
// same instance, which is why the Handler is built here rather than left for
// a caller to construct separately: a caller-built preview.NewHandler(c,
// signer) would be a different object with its own revocation state that
// Revoke could never reach.
func WithPreviews(key []byte, baseURL string) Option {
	return func(c *Client) error {
		signer, err := preview.NewSigner(key)
		if err != nil {
			return err
		}
		if baseURL == "" {
			return fmt.Errorf("%w: preview base URL is empty", sandbox.ErrInvalid)
		}
		c.signer = signer
		c.previewBase = baseURL
		c.previewHandler = preview.NewHandler(c, signer)
		return nil
	}
}

// policyFields reports which policy-bearing options a caller set, by comparing
// a resolved Spec against the library defaults.
//
// Dropping these silently would be the same fault the daemon refuses to
// commit, one layer up: the caller would go on believing a runtime it asked
// for had been applied.
func policyFields(spec sandbox.Spec) []string {
	def := sandbox.NewSpec()
	var set []string
	if spec.Image != def.Image {
		set = append(set, "image")
	}
	if spec.Runtime != def.Runtime {
		set = append(set, "runtime")
	}
	if spec.User != def.User {
		set = append(set, "user")
	}
	if spec.Egress != def.Egress {
		set = append(set, "egress")
	}
	if spec.Resources != def.Resources {
		set = append(set, "resources")
	}
	if spec.Lifetime != def.Lifetime {
		set = append(set, "lifetime")
	}
	// DefaultTimeout and MaxTimeout bound every Exec in the sandbox, the same
	// way Resources and Lifetime do, and live in the profile config exactly
	// like them — WithCommandTimeouts is daemon policy for the same reason.
	if spec.DefaultTimeout != def.DefaultTimeout || spec.MaxTimeout != def.MaxTimeout {
		set = append(set, "timeouts")
	}
	return set
}

// policyFieldsSet reports which policy options opts set, including one set to
// the library default.
//
// A resolved Spec cannot show that: an option written to its default leaves the
// Spec identical to one where nothing was passed. So each option is also applied
// to a Spec holding a value no caller would choose in every policy field, and a
// field that moves was written. That needs no bookkeeping inside package
// sandbox, so it holds for an option a caller defines themselves and for one
// added to package sandbox later. TestEveryCreateOptionIsClassified makes a new
// option an explicit decision.
//
// An option that writes nothing, such as WithResources with every field zero,
// is no intent and is not reported.
func policyFieldsSet(opts ...sandbox.CreateOption) []string {
	set := map[string]bool{}
	for _, f := range policyFields(sandbox.NewSpec(opts...)) {
		set[f] = true
	}
	for _, opt := range opts {
		probe := sentinelSpec()
		opt(&probe)
		for _, f := range policyFieldsWrittenTo(probe) {
			set[f] = true
		}
	}
	var out []string
	for _, f := range policyFieldNames {
		if set[f] {
			out = append(out, f)
		}
	}
	return out
}

// policyFieldNames fixes the order of a rejection message.
var policyFieldNames = []string{"image", "runtime", "user", "egress", "resources", "lifetime", "timeouts"}

// sentinelSpec fills every policy field with a value that is not a default and
// that no option would write on purpose.
func sentinelSpec() sandbox.Spec {
	return sandbox.Spec{
		Image:     "\x00sentinel",
		Runtime:   "\x00sentinel",
		User:      "\x00sentinel",
		Egress:    sandbox.EgressPolicy(-1 << 20),
		Resources: sandbox.Resources{CPUs: -1.5, MemoryBytes: -1, DiskBytes: -1, MaxProcesses: -1},
		Lifetime:  sandbox.Lifetime{IdleTimeout: -time.Nanosecond, MaxAge: -time.Nanosecond},

		DefaultTimeout: -time.Nanosecond,
		MaxTimeout:     -time.Nanosecond,
	}
}

// policyFieldsWrittenTo names the policy fields that no longer hold the sentinel.
func policyFieldsWrittenTo(spec sandbox.Spec) []string {
	sentinel := sentinelSpec()
	var written []string
	if spec.Image != sentinel.Image {
		written = append(written, "image")
	}
	if spec.Runtime != sentinel.Runtime {
		written = append(written, "runtime")
	}
	if spec.User != sentinel.User {
		written = append(written, "user")
	}
	if spec.Egress != sentinel.Egress {
		written = append(written, "egress")
	}
	if spec.Resources != sentinel.Resources {
		written = append(written, "resources")
	}
	if spec.Lifetime != sentinel.Lifetime {
		written = append(written, "lifetime")
	}
	if spec.DefaultTimeout != sentinel.DefaultTimeout || spec.MaxTimeout != sentinel.MaxTimeout {
		written = append(written, "timeouts")
	}
	return written
}

// plural picks the verb form for a policyFields message: one offending field
// reads "runtime is daemon policy"; several read "runtime, egress are".
func plural(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
