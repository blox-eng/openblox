//go:build integration

package docker

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// pullTestImage is small, stable, and not the image the rest of the suite uses,
// so removing it locally cannot disturb anything else.
const pullTestImage = "alpine:3.19"

// A sandbox host is not required to have the image already. Before this, Create
// failed with a bare "No such image" and every deployment needed a manual build
// or pull first.
func TestCreatePullsAnAbsentImage(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()

	// Start from a genuinely absent image, or the test proves nothing.
	_ = exec.Command("docker", "rmi", "-f", pullTestImage).Run()
	if err := exec.Command("docker", "image", "inspect", pullTestImage).Run(); err == nil {
		t.Skipf("%s is still present (in use by another container?); cannot prove the pull", pullTestImage)
	}

	name := "openblox-test-pull"
	_, err := b.Create(ctx, name, sandbox.WithImage(pullTestImage))
	if err != nil {
		t.Fatalf("Create with an absent image = %v, want it pulled", err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.Background(), name) })

	if err := exec.Command("docker", "image", "inspect", pullTestImage).Run(); err != nil {
		t.Errorf("%s is still absent after a successful Create", pullTestImage)
	}
}

// An image that cannot be obtained is its own failure, distinct from a malformed
// request: the reference may be perfectly valid and the registry simply down.
func TestCreateReportsAnUnobtainableImage(t *testing.T) {
	b := newTestBackend(t)

	_, err := b.Create(context.Background(), "openblox-test-noimage",
		sandbox.WithImage("ghcr.io/blox-eng/openblox-does-not-exist:0.0.0"))

	if !errors.Is(err, sandbox.ErrImageUnavailable) {
		t.Fatalf("Create with an unobtainable image = %v, want ErrImageUnavailable", err)
	}
}

// A present image must not be re-resolved on every create. The image is the
// guest's whole userland, so a mutable tag silently changing under a caller is a
// supply-chain surprise, not a convenience.
func TestCreateDoesNotRePullAPresentImage(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()

	before := imageID(t, testImage)
	name := "openblox-test-nopull"
	if _, err := b.Create(ctx, name, sandbox.WithImage(testImage)); err != nil {
		t.Fatalf("Create = %v", err)
	}
	t.Cleanup(func() { _ = b.Destroy(context.Background(), name) })

	if after := imageID(t, testImage); after != before {
		t.Errorf("image id changed %s -> %s; a present image was re-resolved", before, after)
	}
}

func imageID(t *testing.T, ref string) string {
	t.Helper()
	out, err := exec.Command("docker", "image", "inspect", "-f", "{{.Id}}", ref).Output()
	if err != nil {
		t.Fatalf("inspect %s = %v", ref, err)
	}
	return string(out)
}
