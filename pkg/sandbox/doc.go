// Package sandbox defines the openblox contract for running untrusted,
// machine-generated code in disposable Linux sandboxes.
//
// This package holds only interfaces, value types, options, and errors.
// Implementations live in sibling packages — see [github.com/blox-eng/openblox/pkg/docker]
// for the Docker + gVisor backend.
//
// # Secure by default
//
// The zero value of every option is the safe one. A sandbox created with no
// options has no network, dropped capabilities, a read-only root filesystem, a
// non-root user, and bounded CPU, memory, and process count:
//
//	sb, err := backend.Create(ctx, "session-1")                     // locked down
//	sb, err := backend.Create(ctx, "session-1", WithEgress(policy)) // deliberately not
//
// This inverts the common design where a permissive default is hardened by
// remembering the right flags. Forgetting an option here can only make a
// sandbox more restrictive, never less.
//
// # Naming and identity
//
// Sandboxes are addressed by a caller-supplied name, and two calls with the
// same name reach the same sandbox until it is reaped. openblox does not
// interpret the name: multi-tenancy, per-user scoping, and access control
// belong to the caller. Callers separating untrusted principals should hash
// their identity into the name rather than passing it through, since the name
// reaches the container runtime.
package sandbox
