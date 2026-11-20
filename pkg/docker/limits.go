package docker

import (
	"fmt"
	"path"
	"slices"
	"strconv"
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
		ok    bool
		limit string
	}{
		{info.MemoryLimit, "memory"},
		{info.SwapLimit, "swap"},
		{info.PidsLimit, "pids"},
		{info.CPUCfsQuota, "cpu"},
	} {
		if !c.ok {
			return fmt.Errorf("%w: the docker daemon cannot enforce the %s limit; %s (see "+fixDoc+")", sandbox.ErrRuntimeUnavailable, c.limit, limitFix(c.limit))
		}
	}
	// Measured 2026-11-20: with --ignore-cgroups, runsc runs the sandbox in the
	// daemon's own cgroup, and Docker still reports every limit as supported.
	registered := info.Runtimes[runtime]
	// runsc parses flags with Go's flag package, so -x, --x, --x=true and
	// --x=1 all set it.
	ignoresCgroups := false
	for _, arg := range registered.Args {
		name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if name != "ignore-cgroups" {
			continue
		}
		on, err := strconv.ParseBool(value)
		ignoresCgroups = !hasValue || on || err != nil
	}
	if ignoresCgroups {
		return fmt.Errorf("%w: runtime %q runs with --ignore-cgroups, so memory, CPU and process limits do not apply; remove the flag from the runtime's registration (see "+fixDoc+")", sandbox.ErrRuntimeUnavailable, runtime)
	}
	// Under rootless Docker, runsc starts only with that flag. Info carries
	// only Path and Args, so a runtime registered as a containerd shim has no
	// path, and Docker cannot say whether it is runsc.
	runsc := runtime == "runsc" || path.Base(registered.Path) == "runsc" || registered.Path == ""
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
		limit := "resource"
		switch {
		case strings.Contains(lower, "swap"):
			limit = "swap"
		case strings.Contains(lower, "pids"):
			limit = "pids"
		case strings.Contains(lower, "memory"):
			limit = "memory"
		}
		return fmt.Errorf("%w: the docker daemon discarded the %s limit; %s (see "+fixDoc+")", sandbox.ErrRuntimeUnavailable, limit, limitFix(limit))
	}
	return nil
}

// limitFix says how to give the daemon a limit it lacks. Swap is not a
// controller of its own: it needs swap accounting in the kernel.
func limitFix(limit string) string {
	switch limit {
	case "swap":
		return "enable swap accounting: boot the host with swapaccount=1, or move it to cgroup v2"
	case "memory", "pids", "cpu":
		return "enable the " + limit + " cgroup controller for the docker daemon (rootless: delegate it to the daemon's user)"
	default:
		return "enable the memory, cpu and pids cgroup controllers for the docker daemon (rootless: delegate them to the daemon's user)"
	}
}
