package docker

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

func TestCappedBufferKeepsThePrefixAndDrainsTheRest(t *testing.T) {
	b := &cappedBuffer{limit: 8}

	for _, chunk := range []string{"abc", "defgh", "ijk", "lmnop"} {
		// Reporting a short write would make StdCopy stop draining, leaving the
		// guest blocked on a full pipe until its timeout.
		if n, err := b.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write(%q) = %d, %v; want %d, nil", chunk, n, err, len(chunk))
		}
	}

	if got := b.buf.String(); got != "abcdefgh" {
		t.Errorf("kept %q, want the first 8 bytes", got)
	}
	if !b.truncated {
		t.Error("truncated = false after discarding output")
	}
}

func TestCappedBufferAtExactlyTheLimitIsNotTruncated(t *testing.T) {
	b := &cappedBuffer{limit: 4}
	_, _ = b.Write([]byte("abcd"))

	if b.truncated {
		t.Error("truncated = true, but nothing was discarded")
	}
	if !bytes.Equal(b.buf.Bytes(), []byte("abcd")) {
		t.Errorf("kept %q, want abcd", b.buf.Bytes())
	}
}

// With no Docker daemon reachable, Create must fail promptly with an error —
// never hang, and never report a sandbox it did not make.
func TestCreateFailsCleanlyWhenDockerIsUnreachable(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix://"+t.TempDir()+"/no-such-docker.sock")
	b, err := New()
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sb, err := b.Create(ctx, "unreachable", sandbox.WithImage("example.com/i@sha256:abc"))
	if err == nil || sb != nil {
		t.Fatalf("Create = %v, %v; want an error and no sandbox", sb, err)
	}
	if ctx.Err() != nil {
		t.Fatal("Create hung until the deadline instead of failing")
	}
}
