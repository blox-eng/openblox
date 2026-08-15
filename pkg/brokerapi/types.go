// Package brokerapi holds the wire types openbloxd speaks and brokerclient
// consumes. It deliberately mirrors pkg/sandbox rather than re-modelling it:
// the broker exposes the library's surface and nothing more.
package brokerapi

import "time"

// UpgradeProto names the raw stream the dial endpoint switches to. It is not
// a WebSocket: there is no framing, because the payload is an arbitrary byte
// stream both sides already know how to interpret.
const UpgradeProto = "openblox-stream"

// CreateRequest is the whole of what a caller may ask for. Every field that
// could weaken isolation is absent by design and is daemon configuration
// instead — see the profile config. Adding a field here is a security change.
type CreateRequest struct {
	Name    string            `json:"name"`
	Profile string            `json:"profile"`
	Env     []string          `json:"env,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// Info describes a sandbox. Profile is reported so a caller can tell which
// policy a pre-existing sandbox was created under. Labels are exactly the
// caller's own labels from Create — the daemon's own bookkeeping (which
// profile a sandbox belongs to) is never mixed in here, because it is already
// reported separately as Profile.
type Info struct {
	Name      string            `json:"name"`
	ID        string            `json:"id"`
	Image     string            `json:"image"`
	State     string            `json:"state"`
	CreatedAt time.Time         `json:"created_at"`
	Profile   string            `json:"profile"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ExecRequest runs one command. Timeout is a Go duration string; the daemon
// clamps it to the profile's maximum, so it can only narrow.
type ExecRequest struct {
	Argv    []string `json:"argv"`
	Env     []string `json:"env,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	Timeout string   `json:"timeout,omitempty"`
}

// ExecResponse carries raw bytes: a sandbox runs arbitrary programs and its
// output is not guaranteed to be valid UTF-8.
type ExecResponse struct {
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// ProcessRequest starts a detached background process.
type ProcessRequest struct {
	Name string   `json:"name"`
	Argv []string `json:"argv"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
}

// ProfileInfo reports a profile's lifetime bounds. A caller running its own
// reaper needs these to stay ordered behind the daemon's.
type ProfileInfo struct {
	Name        string `json:"name"`
	IdleTimeout string `json:"idle_timeout"`
	MaxAge      string `json:"max_age"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Message string `json:"error"`
	Kind    string `json:"kind"`
}
