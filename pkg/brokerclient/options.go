// Package brokerclient reaches openbloxd over its Unix socket.
//
// Its Client satisfies sandbox.Backend and its handle satisfies
// sandbox.Sandbox, so a caller swaps one constructor and stops needing
// Docker socket access.
package brokerclient

import (
	"fmt"

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
	return set
}

// plural picks the verb form for a policyFields message: one offending field
// reads "runtime is daemon policy"; several read "runtime, egress are".
func plural(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
