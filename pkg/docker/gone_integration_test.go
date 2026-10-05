//go:build integration

package docker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// A client that caches a sandbox handle can only recover if it can tell a
// handle whose sandbox is gone from a broken daemon. The container can vanish
// without the client doing anything: MaxAge, docker rm, a host restart.
func TestOperationsOnRemovedContainerReportNotFound(t *testing.T) {
	b := newTestBackend(t)
	sb := create(t, b, "openblox-test-removed")
	ctx := context.Background()

	if err := b.cli.ContainerRemove(ctx, containerName("openblox-test-removed"), container.RemoveOptions{Force: true}); err != nil {
		t.Fatalf("ContainerRemove: %v", err)
	}

	t.Run("exec", func(t *testing.T) {
		_, err := sb.Exec(ctx, sandbox.Command{Argv: []string{"echo", "hi"}})
		if !errors.Is(err, sandbox.ErrNotFound) {
			t.Errorf("Exec on removed = %v, want ErrNotFound", err)
		}
	})

	t.Run("write file", func(t *testing.T) {
		err := sb.WriteFile(ctx, "/workspace/anything.txt", 0o644, strings.NewReader("x"))
		if !errors.Is(err, sandbox.ErrNotFound) {
			t.Errorf("WriteFile on removed = %v, want ErrNotFound", err)
		}
	})

	t.Run("start process", func(t *testing.T) {
		err := sb.StartProcess(ctx, "job", sandbox.Command{Argv: []string{"sleep", "60"}})
		if !errors.Is(err, sandbox.ErrNotFound) {
			t.Errorf("StartProcess on removed = %v, want ErrNotFound", err)
		}
	})
}
