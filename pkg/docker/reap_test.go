package docker

import (
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func summary(state string, labels map[string]string) container.Summary {
	return container.Summary{ID: "test", State: state, Labels: labels}
}

// A negative bound is how a caller disables it, so unlike the timeout labels a
// negative value must survive parsing rather than falling back to the default.
func TestParseSignedDurationLabelPreservesDisabledBounds(t *testing.T) {
	const fallback = 5 * time.Minute

	tests := map[string]time.Duration{
		"30m":     30 * time.Minute,
		"-1s":     -time.Second,
		"0s":      0,
		"":        fallback,
		"garbage": fallback,
	}
	for label, want := range tests {
		if got := parseSignedDurationLabel(label, fallback); got != want {
			t.Errorf("parseSignedDurationLabel(%q) = %v, want %v", label, got, want)
		}
	}
}

func TestExpiredRequiresACreationTimestamp(t *testing.T) {
	b := &Backend{}
	now := time.Now().UTC()

	// No creation label: openblox cannot tell how old this is, and guessing
	// would mean destroying a caller's data on the strength of a missing field.
	c := summary("running", map[string]string{labelMaxAge: "1s", labelIdle: "1s"})
	if b.expired(t.Context(), c, now) {
		t.Error("reaped a sandbox with no creation timestamp")
	}
}

func TestExpiredEnforcesMaxAge(t *testing.T) {
	b := &Backend{}
	now := time.Now().UTC()

	// Stopped, so no exec is attempted and no daemon is needed.
	c := summary("exited", map[string]string{
		labelCreatedAt: now.Add(-3 * time.Hour).Format(time.RFC3339Nano),
		labelMaxAge:    "1h",
		labelIdle:      "-1s", // idle disabled: this is the max-age path alone
	})
	if !b.expired(t.Context(), c, now) {
		t.Error("a 3h-old sandbox survived a 1h max age")
	}
}

// MaxAge is the bound that must hold no matter what the sandbox does, so it has
// to fire even when the sandbox is not idle at all.
func TestMaxAgeReapsASandboxThatIsNeverIdle(t *testing.T) {
	b := &Backend{}
	now := time.Now().UTC()

	c := summary("exited", map[string]string{
		labelCreatedAt: now.Add(-3 * time.Hour).Format(time.RFC3339Nano),
		labelMaxAge:    "1h",
		labelIdle:      "24h", // nowhere near idle
	})
	if !b.expired(t.Context(), c, now) {
		t.Error("max age did not fire on a sandbox kept warm; it would live forever")
	}
}

func TestExpiredHonoursDisabledBounds(t *testing.T) {
	b := &Backend{}
	now := time.Now().UTC()

	c := summary("exited", map[string]string{
		labelCreatedAt: now.Add(-100 * time.Hour).Format(time.RFC3339Nano),
		labelMaxAge:    "-1s",
		labelIdle:      "-1s",
	})
	if b.expired(t.Context(), c, now) {
		t.Error("reaped a sandbox whose bounds were both disabled")
	}
}

func TestExpiredLeavesAYoungSandboxAlone(t *testing.T) {
	b := &Backend{}
	now := time.Now().UTC()

	c := summary("exited", map[string]string{
		labelCreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
		labelMaxAge:    sandbox.DefaultMaxAge.String(),
		labelIdle:      sandbox.DefaultIdleTimeout.String(),
	})
	if b.expired(t.Context(), c, now) {
		t.Error("reaped a one-minute-old sandbox")
	}
}
