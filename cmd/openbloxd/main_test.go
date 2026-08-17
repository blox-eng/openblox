package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestServeReturnsPromptlyOnAcceptFailure covers a real regression: serve()
// used to only select on ctx.Done(), so a Serve failure with no signal in
// flight left it blocked forever waiting for a signal that would never come.
// A closed listener makes Serve fail on its own immediately, standing in for
// any Accept-loop failure — the assertion is that serve() notices and
// returns without needing ctx to be cancelled.
func TestServeReturnsPromptlyOnAcceptFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Never cancelled: if serve() regresses to selecting only on ctx.Done(),
	// this test hangs until the timeout below fires it as a failure.
	ctx := context.Background()

	done := make(chan error, 1)
	go func() { done <- serve(ctx, &http.Server{}, ln) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve: expected an error from Serve failing on a closed listener, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve() hung instead of returning promptly when Serve failed with no signal")
	}
}

// TestServeShutsDownOnContextCancel exercises the other arm of the same
// select: the signal path must still work now that serve() also races
// against serveErr. This is a structural check that the select didn't break —
// it has no in-flight request to drain, so draining itself is http.Server's
// own documented Shutdown behaviour, not something this test needs to
// reprove.
func TestServeShutsDownOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, &http.Server{}, ln) }()

	// Give the Serve goroutine a moment to start accepting before cancelling,
	// so this exercises the ctx.Done() arm rather than winning the select on
	// a Serve that hasn't even started yet.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not return after ctx cancellation")
	}
}

// TestVersionDefaultsToDev pins the invariant the `version` doc comment argues
// for: an in-tree build must never look like a release. The only thing allowed to
// change this value is -ldflags at release time, so if a refactor ever stamps it
// in the tree — or someone edits the default to a plausible-looking number —
// this fails rather than letting a local build claim a version it does not have.
func TestVersionDefaultsToDev(t *testing.T) {
	if version != "dev" {
		t.Errorf("version = %q in an unstamped build, want %q", version, "dev")
	}
}
