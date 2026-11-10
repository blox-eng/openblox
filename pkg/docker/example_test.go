package docker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/blox-eng/openblox/pkg/docker"
	"github.com/blox-eng/openblox/pkg/preview"
	"github.com/blox-eng/openblox/pkg/sandbox"
)

// Create a sandbox and run a command in it. With no options the sandbox has no
// network, a read-only root filesystem and a non-root user.
func Example() {
	ctx := context.Background()

	backend, err := docker.New()
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()

	// There is no default image. In production, pin a digest instead of a tag.
	sb, err := backend.Create(ctx, "session-1",
		sandbox.WithImage("ghcr.io/blox-eng/openblox-sandbox:latest"))
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Destroy(ctx, "session-1")

	res, err := sb.Exec(ctx, sandbox.Command{
		Argv: []string{"python3", "-c", "print(6 * 7)"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("exit %d: %s", res.ExitCode, res.Stdout)
}

// Create fails rather than run a sandbox with weaker isolation than was asked
// for. These are the errors a caller is expected to tell apart.
func ExampleBackend_Create() {
	ctx := context.Background()
	backend, err := docker.New()
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()

	defer backend.Destroy(ctx, "session-1")
	_, err = backend.Create(ctx, "session-1",
		sandbox.WithImage("ghcr.io/blox-eng/openblox-sandbox:latest"),
		sandbox.WithResources(sandbox.Resources{MemoryBytes: 512 << 20}),
		sandbox.WithLifetime(sandbox.Lifetime{IdleTimeout: 5 * time.Minute}),
	)
	switch {
	case errors.Is(err, sandbox.ErrRuntimeUnavailable):
		// gVisor is not installed or not registered with Docker. Fix the host;
		// retrying does not help.
	case errors.Is(err, sandbox.ErrImageUnavailable):
		// The image is absent and the pull failed. Retrying may succeed.
	case errors.Is(err, sandbox.ErrInvalid):
		// The name or an option is malformed.
	case err != nil:
		log.Fatal(err)
	}
}

// A command that exits non-zero is a result, not an error. An error means the
// command did not run or did not finish.
func Example_exec() {
	ctx := context.Background()
	backend, err := docker.New()
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()
	sb, err := backend.Create(ctx, "session-1",
		sandbox.WithImage("ghcr.io/blox-eng/openblox-sandbox:latest"))
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Destroy(ctx, "session-1")

	res, err := sb.Exec(ctx, sandbox.Command{
		// Argv runs without a shell. Ask for one when the command needs it.
		Argv:    []string{"sh", "-c", "wc -l && exit 3"},
		Stdin:   bytes.NewBufferString("a\nb\n"),
		Env:     []string{"LC_ALL=C"},
		Timeout: 10 * time.Second,
	})
	switch {
	case errors.Is(err, sandbox.ErrTimeout):
		// The command was killed. The sandbox is still usable.
	case errors.Is(err, sandbox.ErrStopped):
		// The sandbox was not running. Create it again under the same name.
	case err != nil:
		log.Fatal(err)
	case res.Stopped:
		// The sandbox died under the command, for example at its memory limit.
		// Its files are gone; res.OOMKilled says whether memory was the cause.
	default:
		fmt.Printf("exit %d, stdout %q, stderr %q\n", res.ExitCode, res.Stdout, res.Stderr)
	}
}

// Send a file in, work on it, and read the result back. Both directions
// stream, so they suit payloads larger than Exec's output cap.
func Example_files() {
	ctx := context.Background()
	backend, err := docker.New()
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()
	sb, err := backend.Create(ctx, "session-1",
		sandbox.WithImage("ghcr.io/blox-eng/openblox-sandbox:latest"))
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Destroy(ctx, "session-1")

	input := bytes.NewBufferString("b\na\n")
	if err := sb.WriteFile(ctx, "/workspace/in.txt", 0o644, input); err != nil {
		log.Fatal(err)
	}
	if _, err := sb.Exec(ctx, sandbox.Command{
		Argv: []string{"sh", "-c", "sort /workspace/in.txt > /workspace/out.txt"},
	}); err != nil {
		log.Fatal(err)
	}

	out, err := sb.ReadFile(ctx, "/workspace/out.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	sorted, err := io.ReadAll(out)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", sorted)
}

// Serve a port inside a sandbox to someone outside it. The sandbox still has
// no network: the handler carries each request in over the exec channel.
func ExampleWithPreviews() {
	ctx := context.Background()

	// Use one key everywhere previews are minted or served, and keep it secret.
	// The base URL is where the handler below is reachable from outside; in
	// production that is an HTTPS address.
	key := make([]byte, preview.MinKeyBytes)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	backend, err := docker.New(docker.WithPreviews(key, "http://127.0.0.1:8080"))
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()

	// openblox runs no server. Mount the handler on your own.
	mux := http.NewServeMux()
	mux.Handle(preview.RoutePrefix+"/", backend.PreviewHandler())
	srv := &http.Server{Addr: "127.0.0.1:8080", Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	defer srv.Close()

	sb, err := backend.Create(ctx, "session-1",
		sandbox.WithImage("ghcr.io/blox-eng/openblox-sandbox:latest"))
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Destroy(ctx, "session-1")
	if err := sb.StartProcess(ctx, "web", sandbox.Command{
		Argv: []string{"python3", "-m", "http.server", "8000", "--bind", "127.0.0.1"},
	}); err != nil {
		log.Fatal(err)
	}

	// StartProcess returns at once, so wait until the server listens.
	if _, err := sb.Exec(ctx, sandbox.Command{
		Argv:    []string{"sh", "-c", "until nc -z 127.0.0.1 8000; do sleep 0.1; done"},
		Timeout: 10 * time.Second,
	}); err != nil {
		log.Fatal(err)
	}

	link, err := sb.Expose(ctx, 8000, 10*time.Minute)
	if err != nil {
		log.Fatal(err)
	}

	// The token is a bearer credential. Send it in the header, never in the URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link.URL+"/", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+link.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)

	// Revoke is prompt cleanup in this process only. The expiry is the bound
	// that always holds.
	if err := sb.Revoke(ctx, 8000, link.Token); err != nil {
		log.Fatal(err)
	}
}
