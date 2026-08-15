package daemon

import (
	"context"
	"log/slog"
	"time"
)

// RunReaper sweeps expired sandboxes until ctx is cancelled.
//
// The daemon owns lifetime now, so it owns the sweep. Nothing ran this before:
// the library wrote idle and max-age labels that no process acted on, so a
// sandbox whose caller vanished lived until someone noticed.
func (s *Server) RunReaper(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reaped, err := s.backend.Reap(ctx)
			if err != nil {
				// One transient Docker error must not silently stop lifetime
				// enforcement for the life of the process.
				slog.Warn("openbloxd: reap sweep failed", slog.Any("error", err))
				continue
			}
			for _, name := range reaped {
				slog.Info("openbloxd: reaped expired sandbox", slog.String("sandbox", name))
			}
		}
	}
}
