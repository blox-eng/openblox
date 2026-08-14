// Command openbloxd brokers the Docker API so callers never need socket access.
//
// It owns the Docker connection and exposes only openblox's own surface, under
// a policy read from its config file. A caller that is compromised can create
// sandboxes, which it can do by design; it cannot mount the host filesystem or
// start a privileged container.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blox-eng/openblox/internal/daemon"
	"github.com/blox-eng/openblox/pkg/docker"
)

func main() {
	configPath := flag.String("config", "/etc/openbloxd/config.yaml", "path to the config file")
	flag.Parse()

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
	for name, p := range cfg.Profiles {
		if !p.DigestPinned() {
			slog.Warn("profile image is not pinned to a digest; whoever controls the registry can repoint the tag",
				slog.String("profile", name), slog.String("image", p.Image))
		}
		if p.RegistryAuth != nil {
			opts = append(opts, docker.WithRegistryAuth(p.RegistryAuth.Username, p.RegistryAuth.Password))
		}
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
	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("openbloxd listening", slog.String("socket", cfg.Socket), slog.Int("profiles", len(cfg.Profiles)))
	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
