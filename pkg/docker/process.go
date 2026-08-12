package docker

import (
	"fmt"
	"path"
	"strings"

	"context"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// rootUser is the identity openblox's own privileged bookkeeping runs as. It is
// never derived from caller input.
const rootUser = "0:0"

// procDir holds one subdirectory per named background process. It lives on the
// scratch tmpfs rather than openblox's state directory because the processes
// themselves run as the sandbox user and must be able to write their own logs.
const procDir = "/tmp/.openblox/proc"

// startProcessScript starts a named process unless one is already running.
//
// The check and the start are one shell invocation so two concurrent
// StartProcess calls cannot both pass the check. $1 is the process directory;
// everything after it is the command, passed as arguments rather than
// interpolated, so no part of it is parsed as shell syntax.
//
// The process is detached from the exec session: stdin comes from /dev/null and
// both output streams go to a log file, so the hijacked connection closes as
// soon as the shell exits rather than staying open for the process's lifetime.
const startProcessScript = `
dir="$1"; shift
if [ -r "$dir/pid" ] && kill -0 "$(cat "$dir/pid")" 2>/dev/null; then exit 0; fi
mkdir -p "$dir" || exit 1
"$@" </dev/null >"$dir/log" 2>&1 &
echo $! > "$dir/pid"
`

// StartProcess starts cmd as a detached background process under name.
//
// It is idempotent: if a process is already running under name, it is left
// running and the new command is not started.
func (s *dockerSandbox) StartProcess(ctx context.Context, name string, cmd sandbox.Command) error {
	if err := validateProcessName(name); err != nil {
		return err
	}
	if err := cmd.Validate(); err != nil {
		return err
	}

	argv := append([]string{
		"sh", "-c", startProcessScript,
		"openblox", path.Join(procDir, name),
	}, cmd.Argv...)

	res, err := s.Exec(ctx, sandbox.Command{
		Argv: argv,
		Env:  cmd.Env,
		Dir:  cmd.Dir,
	})
	if err != nil {
		return fmt.Errorf("start process %q in %q: %w", name, s.info.Name, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("start process %q in %q: exit %d: %s",
			name, s.info.Name, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// validateProcessName keeps a name usable as a single path segment. Without this
// a name like "../../etc" would place the bookkeeping outside procDir.
func validateProcessName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: process name is empty", sandbox.ErrInvalid)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("%w: process name %q starts with a dot", sandbox.ErrInvalid, name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%w: process name %q contains %q; use letters, digits, dot, dash or underscore",
				sandbox.ErrInvalid, name, r)
		}
	}
	return nil
}
