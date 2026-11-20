package docker

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/docker/docker/api/types/system"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// fixDoc is where an operator reads the fix for a host that cannot cap a
// sandbox. TestFixDocResolves holds the anchor in place.
const fixDoc = "docs/security.md#rootless"

// checkDaemonCaps refuses a daemon that would run the sandbox with a limit
// that does not hold. Docker accepts a limit it cannot enforce and only warns,
// so a sandbox would start uncapped and nothing would report it.
func checkDaemonCaps(info system.Info, runtime string) error {
	if info.CgroupDriver == "none" {
		return fmt.Errorf("%w: the docker daemon runs without cgroups, so no memory, CPU or process limit applies; run it with the systemd cgroup driver (see "+fixDoc+")", sandbox.ErrRuntimeUnavailable)
	}
	for _, c := range []struct {
		ok         bool
		limit      string
		controller string
	}{
		{info.MemoryLimit, "memory", "memory"},
		{info.SwapLimit, "swap", "memory"},
		{info.PidsLimit, "pids", "pids"},
		{info.CPUCfsQuota, "cpu", "cpu"},
	} {
		if !c.ok {
			return fmt.Errorf("%w: the docker daemon cannot enforce the %s limit; delegate the %s cgroup controller to the daemon's user (see "+fixDoc+")", sandbox.ErrRuntimeUnavailable, c.limit, c.controller)
		}
	}
	// Measured 2026-11-20: under rootless Docker, runsc starts only with
	// --ignore-cgroups, and the sandbox then runs in the daemon's own cgroup.
	// Docker still reports every limit as supported.
	runsc := runtime == "runsc" || path.Base(info.Runtimes[runtime].Path) == "runsc"
	if slices.Contains(info.SecurityOptions, "name=rootless") && runsc {
		return fmt.Errorf("%w: rootless docker cannot cap a runsc sandbox: runsc runs there only with --ignore-cgroups, so memory, CPU and process limits do not apply; run openbloxd against the root docker daemon (see "+fixDoc+")", sandbox.ErrRuntimeUnavailable)
	}
	return nil
}

// checkLimitWarnings refuses a create whose warnings say Docker dropped a
// limit. It matches keywords, not Docker's sentences, so a reworded warning
// from a later engine is still refused.
func checkLimitWarnings(warnings []string) error {
	for _, w := range warnings {
		lower := strings.ToLower(w)
		if !strings.Contains(lower, "discarded") && !strings.Contains(lower, "without swap") {
			continue
		}
		limit, controllers := "a resource", "memory, cpu and pids cgroup controllers"
		switch {
		case strings.Contains(lower, "swap"):
			limit, controllers = "the swap", "memory cgroup controller"
		case strings.Contains(lower, "pids"):
			limit, controllers = "the pids", "pids cgroup controller"
		case strings.Contains(lower, "memory"):
			limit, controllers = "the memory", "memory cgroup controller"
		}
		return fmt.Errorf("%w: the docker daemon discarded %s limit; delegate the %s to the daemon's user (see "+fixDoc+")", sandbox.ErrRuntimeUnavailable, limit, controllers)
	}
	return nil
}
