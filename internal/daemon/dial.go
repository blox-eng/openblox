package daemon

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"

	"github.com/blox-eng/openblox/pkg/brokerapi"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// handleDial hands the caller a raw stream to a port inside the sandbox.
//
// This is the whole of the daemon's role in previews. The preview handler
// itself runs in the caller, which needs only a byte stream and no Docker
// access, so the browser-facing surface stays out of the process that holds
// the socket.
func (s *Server) handleDial(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		fail(w, fmt.Errorf("%w: port %q is not in 1-65535", sandbox.ErrInvalid, r.PathValue("port")))
		return
	}

	upstream, err := s.backend.DialPort(r.Context(), r.PathValue("name"), port)
	if err != nil {
		fail(w, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	rc := http.NewResponseController(w)
	downstream, buf, err := rc.Hijack()
	if err != nil {
		fail(w, fmt.Errorf("%w: connection cannot be hijacked: %s", sandbox.ErrInvalid, err))
		return
	}
	defer func() { _ = downstream.Close() }()

	if _, err := io.WriteString(downstream,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+brokerapi.UpgradeProto+"\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}

	// Anything the client pipelined behind the request line is already in the
	// buffered reader; reading from the raw connection instead would lose it.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, buf)
		// Half-close so a request whose body has ended is actually seen as
		// ended by the relay; without this a proxied write never completes.
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(downstream, upstream)
	}()
	wg.Wait()
}

func (s *Server) handleProfiles(w http.ResponseWriter, _ *http.Request) {
	out := make([]brokerapi.ProfileInfo, 0, len(s.cfg.Profiles))
	for name, p := range s.cfg.Profiles {
		out = append(out, brokerapi.ProfileInfo{
			Name:        name,
			IdleTimeout: p.IdleTimeout.String(),
			MaxAge:      p.MaxAge.String(),
		})
	}
	// Map iteration order is random; a caller diffing responses across calls
	// needs a stable order.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	respond(w, http.StatusOK, out)
}
