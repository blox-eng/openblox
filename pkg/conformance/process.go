package conformance

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// countProcs reports how many processes in the sandbox have marker in their
// command line. The pattern brackets the marker's first character so it
// matches the marker but not this probe's own command line, which contains
// the pattern text rather than the marker itself.
func countProcs(t *testing.T, sb sandbox.Sandbox, marker string) int {
	t.Helper()
	pattern := "[" + marker[:1] + "]" + marker[1:]
	// pattern is always built from a package constant passed by the caller;
	// shellQuote still makes the interpolation explicit and safe.
	script := `n=0; for f in /proc/[0-9]*/cmdline; do tr '\0' ' ' 2>/dev/null <"$f" | grep -q ` +
		shellQuote(pattern) + ` && n=$((n+1)); done; echo $n`
	// Processes come and go while the loop runs, so a read can fail; stderr
	// is silenced above so a failed read is silent too, and only stdout is
	// parsed.
	res, err := sb.Exec(t.Context(), sandbox.Command{Argv: []string{"sh", "-c", script}})
	if err != nil {
		t.Fatalf("count processes: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if err != nil {
		t.Fatalf("count processes: %q", res.Stdout)
	}
	return n
}

// A timeout that only stops the caller waiting is not a timeout: the command,
// and anything it started, would burn the sandbox's CPU until it was reaped.
func propTimedOutCommandKillsChildren(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-timeoutkill")

	_, err := sb.Exec(t.Context(), sandbox.Command{
		Argv:    []string{"sh", "-c", "sleep 3131 & sleep 3132 & while :; do :; done"},
		Timeout: 2 * time.Second,
	})
	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("%s: Exec = %v, want ErrTimeout", cfg.Name, err)
	}
	if n := countProcs(t, sb, "sleep 313"); n != 0 {
		t.Errorf("%s: %d child processes outlived the timeout", cfg.Name, n)
	}
	if n := countProcs(t, sb, "while :; do :; done"); n != 0 {
		t.Errorf("%s: the timed-out command itself is still running (%d)", cfg.Name, n)
	}
	// The sandbox stays usable, as ErrTimeout promises.
	if out := run(t, sb, "echo alive"); !strings.Contains(out, "alive") {
		t.Errorf("%s: sandbox unusable after a timeout: %q", cfg.Name, out)
	}
}

// Cancellation — a caller giving up, or a broker client disconnecting — must
// stop the command the same way a timeout does, and must not be reported as
// one.
func propCancelledCommandIsNotATimeout(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-cancel")

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(time.Second, cancel)
	_, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sleep", "3133"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%s: Exec = %v, want context.Canceled", cfg.Name, err)
	}
	if errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("%s: Exec = %v, cancellation must not also report ErrTimeout", cfg.Name, err)
	}
	if n := countProcs(t, sb, "sleep 3133"); n != 0 {
		t.Errorf("%s: cancelled command still running (%d)", cfg.Name, n)
	}
}

// The kill must not give up on a command just because it has not yet had the
// chance to record itself as running: an implementation that only started
// looking for what to kill after some bookkeeping step of its own would leave
// exactly the command whose kill raced that bookkeeping running past its
// deadline. This drives the timeout to the shortest duration the interface
// still resolves reliably, which puts the command and its kill in the
// tightest race a caller outside the backend can force.
//
// The original form of this property staged the race directly against
// openblox's docker backend: it reached into the unexported dockerSandbox to
// call killGroup before the unexported exec wrapper had written its own
// process-group record. That is not expressible here. Core properties run
// against any sandbox.Backend, and this package depends on nothing but
// pkg/sandbox, so there is no backend-specific hook left to reach into. An
// effectively-immediate Timeout is the closest black-box equivalent: it
// forces the same "the kill starts looking before there is anything to find"
// window through the public interface alone.
func propKillGroupWaitsForLateRecord(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-killwait")

	const marker = "sleep 3137"
	_, err := sb.Exec(t.Context(), sandbox.Command{
		Argv:    []string{"sh", "-c", "exec " + marker},
		Timeout: 100 * time.Millisecond,
	})
	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("%s: Exec = %v, want ErrTimeout", cfg.Name, err)
	}
	if n := countProcs(t, sb, marker); n != 0 {
		t.Errorf("%s: the kill gave up before a record of the command existed: %d still running", cfg.Name, n)
	}
}

// The kill is scoped to the timed-out command's own process group. A
// background process started earlier — a preview server, say — must survive
// another command timing out.
func propTimeoutKillIsScopedToItsCommand(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-killscope")
	ctx := t.Context()

	if err := sb.StartProcess(ctx, "server", sandbox.Command{Argv: []string{"sleep", "3135"}}); err != nil {
		t.Fatalf("%s: StartProcess = %v", cfg.Name, err)
	}
	_, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"sh", "-c", "while :; do :; done"}, Timeout: time.Second})
	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("%s: Exec = %v, want ErrTimeout", cfg.Name, err)
	}
	if n := countProcs(t, sb, "sleep 3135"); n != 1 {
		t.Errorf("%s: background process count = %d after an unrelated timeout, want 1", cfg.Name, n)
	}
}

// A process that leaves the group with setsid survives the kill. That is the
// documented limit, pinned here so the documentation stays true: what bounds
// such a process is the sandbox's CPU and process caps, its lifetime, and
// Destroy.
//
// This is a known ESCAPE, not a defence, and it stays in Core exactly as
// written. A suite that quietly dropped the properties recording its own
// implementation's known limitations would overstate every implementation it
// measures, openblox's own included — and this property's name is what makes
// that legible to someone reading only the output.
func propSetsidEscapesTheTimeoutKill(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-setsid")

	// The pinned reference image is not caller-configurable, so its absence
	// of setsid is a hard failure, not a reason to skip: Core never skips.
	if out := run(t, sb, "command -v setsid || echo MISSING"); strings.Contains(out, "MISSING") {
		t.Fatalf("%s: probe requires setsid, which the pinned reference image must provide: %q", cfg.Name, out)
	}
	_, err := sb.Exec(t.Context(), sandbox.Command{
		Argv:    []string{"sh", "-c", "setsid sleep 3136 </dev/null >/dev/null 2>&1 & while :; do :; done"},
		Timeout: time.Second,
	})
	if !errors.Is(err, sandbox.ErrTimeout) {
		t.Fatalf("%s: Exec = %v, want ErrTimeout", cfg.Name, err)
	}
	if n := countProcs(t, sb, "sleep 3136"); n != 1 {
		t.Errorf("%s: setsid process count = %d; if the kill now reaches it, update ErrTimeout's documentation", cfg.Name, n)
	}
}

func propOutputFloodIsCapped(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-flood")

	res, err := sb.Exec(t.Context(), sandbox.Command{
		Argv: []string{"sh", "-c", `head -c 50000000 /dev/zero; head -c 50000000 /dev/zero >&2; exit 4`},
	})
	if err != nil {
		t.Fatalf("%s: Exec = %v", cfg.Name, err)
	}
	if !res.Truncated {
		t.Errorf("%s: Truncated = false after 50 MB on each stream", cfg.Name)
	}
	if len(res.Stdout) != sandbox.MaxOutputBytes || len(res.Stderr) != sandbox.MaxOutputBytes {
		t.Errorf("%s: kept %d/%d bytes, want %d on each", cfg.Name, len(res.Stdout), len(res.Stderr), sandbox.MaxOutputBytes)
	}
	if res.ExitCode != 4 {
		t.Errorf("%s: exit code = %d, want 4: the stream must be drained so the command finishes", cfg.Name, res.ExitCode)
	}
}
