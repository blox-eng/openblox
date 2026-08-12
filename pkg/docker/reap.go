package docker

import (
	"context"
	"errors"
	"fmt"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Reap destroys sandboxes that have outlived their bounds and returns the names
// it destroyed. Call it from a ticker; it holds no state and several processes
// may run it concurrently against the same daemon.
//
// Each sandbox carries its own bounds, recorded as labels when it was created,
// so a reaper reclaims sandboxes it knows nothing about — including ones created
// before it started. A bound recorded as zero or negative is disabled.
//
// Two bounds, and they are not redundant. Idle reclaims the common case: a
// sandbox nobody came back to. MaxAge catches what idle cannot — a sandbox kept
// permanently warm by a wedged or deliberately busy background process is never
// idle, and without MaxAge it would live forever.
//
// Errors reaping one sandbox do not stop the sweep; they are joined and returned
// once every sandbox has been considered.
func (b *Backend) Reap(ctx context.Context) ([]string, error) {
	containers, err := b.cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("label", labelManaged+"=true")),
	})
	if err != nil {
		return nil, fmt.Errorf("list sandboxes to reap: %w", err)
	}

	now := time.Now().UTC()
	var (
		reaped []string
		errs   []error
	)
	for _, c := range containers {
		name := c.Labels[labelName]
		if !b.expired(ctx, c, now) {
			continue
		}
		err := b.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true, RemoveVolumes: true})
		// Another reaper getting there first is the expected outcome of a
		// concurrent sweep, not a failure.
		if err != nil && !cerrdefs.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("reap sandbox %q: %w", name, err))
			continue
		}
		reaped = append(reaped, name)
	}
	return reaped, errors.Join(errs...)
}

// expired reports whether a sandbox has passed either of its bounds.
func (b *Backend) expired(ctx context.Context, c container.Summary, now time.Time) bool {
	created := parseTimeLabel(c.Labels[labelCreatedAt])
	if created.IsZero() {
		// No creation timestamp means openblox cannot reason about this
		// sandbox's age at all. Leave it: destroying data on the strength of a
		// missing label is the worse failure.
		return false
	}

	if maxAge := parseSignedDurationLabel(c.Labels[labelMaxAge], sandbox.DefaultMaxAge); maxAge > 0 {
		if now.Sub(created) > maxAge {
			return true
		}
	}

	idle := parseSignedDurationLabel(c.Labels[labelIdle], sandbox.DefaultIdleTimeout)
	if idle <= 0 {
		return false
	}

	// A stopped sandbox has no tmpfs to read the activity timestamp from, so its
	// idle clock runs from creation. It is holding disk, not CPU, and MaxAge
	// still applies.
	since := created
	if stateFromStatus(c.State) == sandbox.StateRunning {
		if last := b.lastUsedOf(ctx, c.ID); !last.IsZero() {
			since = last
		}
	}
	return now.Sub(since) > idle
}

// lastUsedOf reads the activity timestamp out of a container by ID.
func (b *Backend) lastUsedOf(ctx context.Context, id string) time.Time {
	s := &dockerSandbox{
		cli:            b.cli,
		id:             id,
		defaultTimeout: sandbox.DefaultCommandTimeout,
		maxTimeout:     sandbox.MaxCommandTimeout,
	}
	return s.lastUsed(ctx)
}

// parseSignedDurationLabel is parseDurationLabel for bounds a caller may
// deliberately disable: a negative value is meaningful and is preserved, while
// an unparseable one falls back to the default.
func parseSignedDurationLabel(v string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
