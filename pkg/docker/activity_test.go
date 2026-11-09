package docker

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestLastUsedReadsTheRecordedTime(t *testing.T) {
	d := &execDaemon{session: replies("2026-11-09T10:00:00.123456789Z\n", "")}
	s := newExecDaemon(t, d)

	got := s.lastUsed(context.Background())

	want := time.Date(2026, 11, 9, 10, 0, 0, 123456789, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("lastUsed = %v, want %v", got, want)
	}
	// Reading the timestamp needs no privilege, so it runs as the sandbox's
	// own user.
	if opts := d.nextCreate(t); opts.User != "" || !slices.Equal(opts.Cmd, []string{"cat", lastUsedPath}) {
		t.Fatalf("exec = user %q argv %q, want the sandbox user running cat %s", opts.User, opts.Cmd, lastUsedPath)
	}
}

// Every way the timestamp can be unreadable reports the zero time, which the
// reaper reads as "fall back to the creation time". None of them may report a
// time that is not there.
func TestLastUsedIsZeroWhenTheTimestampCannotBeRead(t *testing.T) {
	cases := map[string]*execDaemon{
		"never written":     {session: replies("", "cat: /run/openblox/last-used: No such file or directory\n"), exitCode: 1},
		"malformed":         {session: replies("yesterday\n", "")},
		"empty":             {session: replies("", "")},
		"wrong format":      {session: replies("2026-11-09 10:00:00\n", "")},
		"sandbox stopped":   {createStatus: http.StatusConflict},
		"sandbox removed":   {createStatus: http.StatusNotFound},
		"daemon failing":    {createStatus: http.StatusInternalServerError},
		"read stays silent": {session: func(net.Conn, *bufio.Reader) {}, exitCode: 0},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			s := newExecDaemon(t, d)
			if got := s.lastUsed(context.Background()); !got.IsZero() {
				t.Fatalf("lastUsed = %v, want the zero time", got)
			}
		})
	}
}

// The write is privileged and its value is the host's clock, passed as an
// argument rather than spliced into the script. Together these are what stop
// the guest from moving its own idle deadline.
func TestTouchWritesTheHostClockAsRoot(t *testing.T) {
	d := &execDaemon{}
	s := newExecDaemon(t, d)

	before := time.Now()
	s.touch(context.Background())
	opts := d.nextCreate(t)
	after := time.Now()

	if opts.User != rootUser {
		t.Fatalf("touch runs as %q, want %q", opts.User, rootUser)
	}
	if len(opts.Cmd) != 4 || !slices.Equal(opts.Cmd[:3], []string{"sh", "-c", `echo "$0" > ` + lastUsedPath}) {
		t.Fatalf("touch argv = %q, want the timestamp as $0 of a fixed script", opts.Cmd)
	}
	stamp, err := time.Parse(time.RFC3339Nano, opts.Cmd[3])
	if err != nil {
		t.Fatalf("touch wrote %q: %v", opts.Cmd[3], err)
	}
	if stamp.Before(before) || stamp.After(after) {
		t.Fatalf("touch wrote %v, want a time between %v and %v", stamp, before, after)
	}
}

// What touch writes, lastUsed must read back unchanged, to the nanosecond.
func TestLastUsedReadsBackWhatTouchWrote(t *testing.T) {
	writer := &execDaemon{}
	newExecDaemon(t, writer).touch(context.Background())
	written := writer.nextCreate(t).Cmd[3]
	want, _ := time.Parse(time.RFC3339Nano, written)

	reader := &execDaemon{session: replies(written+"\n", "")}
	if got := newExecDaemon(t, reader).lastUsed(context.Background()); !got.Equal(want) {
		t.Fatalf("lastUsed = %v after touch wrote %q", got, written)
	}
}

// touch runs after every Exec. A sandbox slow to accept the write must not
// make the caller's command slower.
func TestTouchDoesNotWaitForTheWrite(t *testing.T) {
	release := make(chan struct{})
	d := &execDaemon{session: func(net.Conn, *bufio.Reader) { <-release }}
	s := newExecDaemon(t, d)
	t.Cleanup(func() { close(release) })

	done := make(chan struct{})
	go func() {
		s.touch(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("touch blocked on the write")
	}
	d.nextCreate(t)
}

// Exec's caller often cancels its context the moment the command returns.
// The write happens after that, so it must not inherit the cancellation.
func TestTouchSurvivesACancelledContext(t *testing.T) {
	d := &execDaemon{}
	s := newExecDaemon(t, d)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.touch(ctx)

	d.nextCreate(t)
}
