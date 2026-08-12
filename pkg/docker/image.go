package docker

import (
	"context"
	"fmt"
	"io"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/image"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// ensureImage makes the image available locally, pulling it if it is absent.
//
// Pull-if-absent rather than always-pull, deliberately. A sandbox image is the
// guest's entire userland, so re-resolving a mutable tag on every Create would
// mean the code running in the sandbox could change under the caller without
// anything in their configuration changing. Absent means fetch; present means
// use what is here.
//
// The corollary is that a tag is only as trustworthy as the moment it was first
// pulled. Pin a digest — see [sandbox.WithImage] — and this becomes exact.
func (b *Backend) ensureImage(ctx context.Context, ref string) error {
	if _, err := b.cli.ImageInspect(ctx, ref); err == nil {
		return nil
	} else if !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("inspect image %q: %w", ref, err)
	}

	body, err := b.cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("%w: pull image %q: %w", sandbox.ErrImageUnavailable, ref, err)
	}
	defer func() { _ = body.Close() }()

	// The pull is only complete once the response body is drained: the daemon
	// streams progress and does the work as it is read, so returning early would
	// leave the image half-fetched and the create failing right behind it.
	if _, err := io.Copy(io.Discard, body); err != nil {
		return fmt.Errorf("%w: pull image %q: %w", sandbox.ErrImageUnavailable, ref, err)
	}

	// Confirm rather than trust the stream: the pull API reports some failures
	// inside the progress body with a 200 status.
	if _, err := b.cli.ImageInspect(ctx, ref); err != nil {
		return fmt.Errorf("%w: image %q is still absent after pulling", sandbox.ErrImageUnavailable, ref)
	}
	return nil
}

// IsDigestPinned reports whether ref names an image by digest rather than by a
// tag. A tag can be repointed by whoever controls the registry; a digest cannot.
func IsDigestPinned(ref string) bool {
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return false
	}
	return strings.HasPrefix(ref[at+1:], "sha256:")
}
