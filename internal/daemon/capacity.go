package daemon

import (
	"context"
	"fmt"
	"sync"

	"github.com/blox-eng/openblox/pkg/brokerapi"
)

// capacity bounds how many sandboxes a profile may hold at once.
//
// A profile bounds what ONE sandbox consumes. Nothing else bounds how many
// exist, and N sandboxes each sitting at their ceiling is N times that ceiling
// of committed host memory — reached without any single request violating a
// policy. Concurrent count is the one resource dimension the profile model does
// not otherwise cover.
//
// The count comes from the backend rather than from a number this process
// keeps, because the backend is the authority: sandboxes survive a daemon
// restart, and a counter that did not would drift into permitting more than the
// cap on exactly the reboot where it mattered. It also means the reaper
// releases capacity for free — an idle sweep, a max_age expiry or an explicit
// Destroy frees a slot with no extra bookkeeping.
type capacity struct {
	mu sync.Mutex
	// pending counts reservations held by requests that have passed the check
	// but whose Create has not returned yet. Without it, several concurrent
	// requests all read the same pre-create count and all pass — a retry storm
	// is precisely the case the cap exists for, so the check has to be atomic
	// with taking the slot.
	pending map[string]int
}

// reserve takes a slot for profile, or reports ErrAtCapacity. The returned
// release must be called once the create attempt has finished, whether or not
// it succeeded.
//
// A limit of zero means unlimited, so a deployment that never configures one is
// unchanged. In that case there is nothing to serialise and no backend call to
// make.
func (c *capacity) reserve(ctx context.Context, s *Server, profile string, limit int) (release func(), err error) {
	if limit <= 0 {
		return func() {}, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	live, err := s.countLive(ctx, profile)
	if err != nil {
		return nil, err
	}
	if live+c.pending[profile] >= limit {
		return nil, fmt.Errorf("%w: profile %q holds %d of %d sandboxes",
			brokerapi.ErrAtCapacity, profile, live+c.pending[profile], limit)
	}

	if c.pending == nil {
		c.pending = map[string]int{}
	}
	c.pending[profile]++
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		// Released only after Create has returned, so a sandbox that was
		// created is already visible to countLive before it stops being
		// counted here. The overlap double-counts for an instant, which errs
		// towards refusing one request too many rather than admitting one too
		// many.
		if c.pending[profile]--; c.pending[profile] <= 0 {
			delete(c.pending, profile)
		}
	}, nil
}

// countLive reports how many sandboxes currently exist under profile.
//
// Stopped sandboxes count. They hold no memory right now, but Backend.Create
// restarts one under the same name, so excluding them would let a caller walk
// past the cap simply by reviving what the reaper has not yet collected.
func (s *Server) countLive(ctx context.Context, profile string) (int, error) {
	all, err := s.backend.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, i := range all {
		if i.Labels[labelProfile] == profile {
			n++
		}
	}
	return n, nil
}
