package daemon

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// labelProfile records which policy a sandbox was created under, so a later
// Create under a different profile can be refused rather than silently served
// the existing sandbox.
const labelProfile = "openbloxd.profile"

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[brokerapi.CreateRequest](w, r)
	if !ok {
		return
	}
	if req.Name == "" {
		fail(w, fmt.Errorf("%w: name is empty", sandbox.ErrInvalid))
		return
	}
	profile, ok := s.cfg.Profiles[req.Profile]
	if !ok {
		fail(w, fmt.Errorf("%w: no profile named %q", sandbox.ErrInvalid, req.Profile))
		return
	}

	// Refuse before creating: an existing sandbox under another profile must not
	// be handed back as though it satisfied this request. Backend.Create returns
	// the live sandbox when the name exists, so the check has to happen here,
	// ahead of that call.
	var exists bool
	if existing, err := s.backend.Open(r.Context(), req.Name); err == nil {
		if got := existing.Info().Labels[labelProfile]; got != req.Profile {
			fail(w, fmt.Errorf("%w: %q exists under profile %q, requested %q",
				brokerapi.ErrProfileConflict, req.Name, got, req.Profile))
			return
		}
		exists = true
	} else if !errors.Is(err, sandbox.ErrNotFound) {
		fail(w, err)
		return
	}

	// Only a NEW name consumes a slot. A sandbox that already exists is already
	// counted, so re-creating it — the session-affinity path a caller takes to
	// reuse its own warm sandbox — must not be refused. Charging it again would
	// starve exactly the callers already inside the cap, and only once the host
	// was busy enough for the cap to bind.
	if !exists {
		release, err := s.cap.reserve(r.Context(), s, req.Profile, profile.MaxSandboxes)
		if err != nil {
			fail(w, err)
			return
		}
		defer release()
	}

	// Profile options first, caller options second — and the caller's are only
	// ever env and labels. Nothing here can reach Runtime or Egress.
	opts := profile.Options()
	opts = append(opts, sandbox.WithLabel(labelProfile, req.Profile))
	if len(req.Env) > 0 {
		opts = append(opts, sandbox.WithEnv(req.Env...))
	}
	for k, v := range req.Labels {
		if k == labelProfile {
			fail(w, fmt.Errorf("%w: label %q is reserved", sandbox.ErrInvalid, labelProfile))
			return
		}
		opts = append(opts, sandbox.WithLabel(k, v))
	}

	sb, err := s.backend.Create(r.Context(), req.Name, opts...)
	if err != nil {
		fail(w, err)
		return
	}

	// The Open check above closes the window before Create, not the one during
	// it: Create returns the EXISTING sandbox when the name is taken, so a
	// concurrent request can win the race and create it under a different
	// profile between our check and this call. Re-check on what Create actually
	// handed back. Do not destroy it — we did not create it, and destroying
	// another request's sandbox out from under it would be worse than the bug
	// this guards against. Refuse and let the caller retry.
	info := sb.Info()
	if got := info.Labels[labelProfile]; got != req.Profile {
		fail(w, fmt.Errorf("%w: %q exists under profile %q, requested %q",
			brokerapi.ErrProfileConflict, req.Name, got, req.Profile))
		return
	}
	respond(w, http.StatusCreated, infoOf(info, info.Labels[labelProfile]))
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	info := sb.Info()
	respond(w, http.StatusOK, infoOf(info, info.Labels[labelProfile]))
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	all, err := s.backend.List(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]brokerapi.Info, 0, len(all))
	for _, i := range all {
		out = append(out, infoOf(i, i.Labels[labelProfile]))
	}
	respond(w, http.StatusOK, out)
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.Destroy(r.Context(), r.PathValue("name")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	sb, err := s.backend.Open(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	if err := sb.Stop(r.Context()); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func infoOf(i sandbox.Info, profile string) brokerapi.Info {
	return brokerapi.Info{
		Name:      i.Name,
		ID:        i.ID,
		Image:     i.Image,
		State:     string(i.State),
		CreatedAt: i.CreatedAt,
		Profile:   profile,
		Labels:    callerLabels(i.Labels),
	}
}

// callerLabels strips the daemon's own bookkeeping label before a sandbox's
// labels go out over the wire. labelProfile is already reported separately as
// Info.Profile; leaving it in the label map too would leak internal
// bookkeeping into the caller's own namespace, exactly what
// pkg/docker's userLabels helper exists to prevent for the layer below this
// one.
func callerLabels(labels map[string]string) map[string]string {
	if _, ok := labels[labelProfile]; !ok {
		return labels
	}
	out := make(map[string]string, len(labels)-1)
	for k, v := range labels {
		if k != labelProfile {
			out[k] = v
		}
	}
	return out
}
