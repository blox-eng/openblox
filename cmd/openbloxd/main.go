// Command openbloxd brokers the Docker API so callers never need socket access.
//
// It owns the Docker connection and exposes only openblox's own surface, under
// a policy read from its config file. A caller that is compromised can create
// sandboxes, which it can do by design; it cannot mount the host filesystem or
// start a privileged container.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blox-eng/openblox/internal/daemon"
	"github.com/blox-eng/openblox/pkg/docker"
)

// version is stamped at build time with -ldflags "-X main.version=<tag>".
//
// It defaults to "dev" rather than a plausible-looking number because an
// unstamped binary is someone's local build, and a daemon installed on a host
// should not claim to be a release it is not. The client and the daemon must
// agree on the wire format, so "what is actually running here" is a question an
// operator has to be able to answer.
var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/openbloxd/config.yaml", "path to the config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if err := run(*configPath); err != nil {
		slog.Error("openbloxd: exiting", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := daemon.Load(configPath)
	if err != nil {
		return err
	}

	var opts []docker.Option
	// One Docker connection carries one credential, and Config.validate has
	// already refused profiles whose registry_auth differs — so every non-nil
	// value here is the same one, and applying it once says that plainly.
	var auth *daemon.RegistryAuth
	for name, p := range cfg.Profiles {
		if !p.DigestPinned() {
			slog.Warn("profile image is not pinned to a digest; whoever controls the registry can repoint the tag",
				slog.String("profile", name), slog.String("image", p.Image))
		}
		if p.RegistryAuth != nil && auth == nil {
			auth = p.RegistryAuth
		}
	}
	if auth != nil {
		opts = append(opts, docker.WithRegistryAuth(auth.Username, auth.Password))
	}

	backend, err := docker.New(opts...)
	if err != nil {
		return err
	}
	defer func() { _ = backend.Close() }()

	ln, err := daemon.Listen(cfg.Socket, cfg.SocketGroup)
	if err != nil {
		return err
	}

	srv := daemon.New(backend, cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go srv.RunReaper(ctx)

	// No read or write timeout: exec can legitimately run for minutes and a
	// dialled preview stream is open for as long as the page is. The library's
	// own command timeouts are the bound that applies here.
	//
	// ReadHeaderTimeout is different: it only bounds the time to read the
	// request line and headers, which completes before Hijack (dial.go) or
	// the handler body (exec.go) ever runs — so it can't truncate a long exec
	// or a long-lived dialled stream. It closes a real Slowloris hole (a peer
	// that trickles headers forever) on the socket that holds the Docker
	// connection, even though that peer is local.
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}

	slog.Info("openbloxd listening", slog.String("socket", cfg.Socket), slog.Int("profiles", len(cfg.Profiles)))
	return serve(ctx, httpSrv, ln)
}

// serve runs httpSrv on ln until ctx is cancelled or Serve fails on its own.
//
// A Serve failure with no signal must return promptly rather than wait on
// ctx.Done(), which may never fire: Restart=on-failure in the unit only
// triggers if the process actually exits, and a process that hangs after
// Serve dies looks "active (running)" to systemd while accepting nothing.
func serve(ctx context.Context, httpSrv *http.Server, ln net.Listener) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.Serve(ln) }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	// Shutdown closes the listener the instant it's called, before it starts
	// waiting on in-flight connections — so it must run synchronously here and
	// block until it (or its 10s budget) is done. Do this on a goroutine
	// instead and the caller returns the moment Serve unblocks, killing that
	// goroutine mid-wait and turning the grace period into dead code.
	//
	// This still can't wait out a hijacked preview stream: once a connection is
	// hijacked it's invisible to Shutdown's in-flight accounting, so the 10s
	// budget — not a graceful drain — is what bounds it.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("openbloxd: graceful shutdown did not complete in time", slog.Any("error", err))
	}

	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
