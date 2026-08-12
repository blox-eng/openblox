package docker

import (
	"errors"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// A process name becomes a path segment, so anything that could climb out of
// procDir has to be refused before it reaches the shell.
func TestValidateProcessNameRejectsPathTraversal(t *testing.T) {
	for _, name := range []string{
		"", "..", "../../etc", "a/b", "a\\b", "with space",
		".hidden", "semi;colon", "dollar$sign", "quote\"", "back`tick`", "new\nline",
	} {
		if err := validateProcessName(name); !errors.Is(err, sandbox.ErrInvalid) {
			t.Errorf("validateProcessName(%q) = %v, want ErrInvalid", name, err)
		}
	}
}

func TestValidateProcessNameAcceptsOrdinaryNames(t *testing.T) {
	for _, name := range []string{"server", "web-1", "api_v2", "job.2026", "A1"} {
		if err := validateProcessName(name); err != nil {
			t.Errorf("validateProcessName(%q) = %v, want nil", name, err)
		}
	}
}
