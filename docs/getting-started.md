# Quick start

## Prerequisites

**A Docker daemon**, and **gVisor (`runsc`) registered with it**.

openblox will not run a sandbox without gVisor. It does not fall back to `runc`, and
that refusal is deliberate: falling back would silently run untrusted code on the host
kernel while the API kept reporting success.

Install gVisor per the [official instructions](https://gvisor.dev/docs/user_guide/install/),
then register it:

```json title="/etc/docker/daemon.json"
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  }
}
```

```sh
sudo systemctl reload docker
docker info --format '{{json .Runtimes}}' | grep runsc   # confirm
```

If `runsc` is absent, `Create` returns an error wrapping `sandbox.ErrRuntimeUnavailable`
— branch on that if you want to degrade gracefully rather than fail.

## Install

```sh
go get github.com/blox-eng/openblox
```

## Run something

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/blox-eng/openblox/pkg/docker"
    "github.com/blox-eng/openblox/pkg/sandbox"
)

func main() {
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
        Argv: []string{"python3", "-c", "print(6 * 7)"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(res.Stdout)) // 42
}
```

`Create` is keyed by name: calling it again with the same name returns the existing
sandbox rather than a second one. That makes it safe to call per request without
tracking what already exists.

A non-zero `res.ExitCode` is the program failing, not an openblox error. `err` is
reserved for openblox failing to run it at all.

!!! note "Argv, not a shell string"
    `Command.Argv` is passed directly to `exec`. Nothing in it is parsed as shell
    syntax, so a caller cannot accidentally create an injection by interpolating
    untrusted text into a command line.

## Files

```go
err := sb.WriteFile(ctx, "/workspace/data.csv", 0o644, strings.NewReader("a,b\n1,2\n"))

rc, err := sb.ReadFile(ctx, "/workspace/out.json")
defer rc.Close()
body, err := io.ReadAll(rc)
```

Both stream, so they are safe for large payloads. Paths are absolute inside the
sandbox; `/workspace` is the working directory and is writable.

## Background processes

```go
err := sb.StartProcess(ctx, "web", sandbox.Command{
    Argv: []string{"python3", "-m", "http.server", "8080", "--bind", "127.0.0.1"},
})
```

Idempotent: if something is already running under that name, it is left alone and no
error is returned. Call it on every request rather than tracking state yourself.

## Preview links

A sandbox has **no network interface**, so a port inside it is not reachable by any
ordinary route. openblox reaches it over the exec channel and fronts it with a signed,
expiring URL.

```go
backend, err := docker.New(
    docker.WithPreviews(signingKey, "https://example.com"), // key >= 32 random bytes
)

// Mount the handler where the signed URLs will resolve.
http.Handle(preview.RoutePrefix+"/", backend.PreviewHandler())

p, err := sb.Expose(ctx, 8080, 10*time.Minute)
// p.URL + p.Token — send the token as an Authorization header, never a query param.
```

!!! warning "Revocation is best-effort; expiry is the guarantee"
    Verification is a local HMAC check that consults no shared state, so `Revoke` only
    holds in the process that recorded it. If you run several replicas, treat the TTL
    as the real bound and keep it short.

## Cleaning up

```go
removed, err := backend.Reap(ctx)   // destroys sandboxes past idle timeout or max age
```

Call it from a ticker. It is safe to run concurrently with everything else, and safe to
run from several processes at once.

## Defaults

A sandbox created with no options gets:

| | |
|---|---|
| Runtime | `runsc` (gVisor) |
| Network | none |
| User | `1000:1000` (non-root) |
| Root filesystem | read-only |
| CPUs | 2 |
| Memory | 2 GiB |
| Scratch disk | 1 GiB (tmpfs, drawn **from** the memory budget) |
| Max processes | 256 |
| Idle timeout | 15 minutes |
| Max age | 2 hours |
| Command timeout | 60s default, 10m ceiling |

Scratch space is tmpfs, so it comes out of memory — keep disk at or below memory, and
size both deliberately if your workload is heavy.
