package conformance

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

const helperLeakEnv = "OPENBLOX_CONFORMANCE_HELPER_LEAK"

// TestHelperLeaksABusyLoop is the subprocess for the two tests below. It makes
// badSandbox leak the way the timeout properties do: a busy loop and a sleep
// that outlive the kill of the direct process. With the env set to "hang" it
// then reports and blocks, so the parent can kill it before TestMain cleans up.
func TestHelperLeaksABusyLoop(t *testing.T) {
	mode := os.Getenv(helperLeakEnv)
	if mode == "" {
		t.Skip("helper process only; run via TestNoProcessOutlives*")
	}
	_, err := badSandbox{}.Exec(context.Background(), sandbox.Command{
		Argv:    []string{"sh", "-c", "sleep 3139 & while :; do :; done"},
		Timeout: 200 * time.Millisecond,
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Exec = %v", err)
	}
	if got := ownedProcs(ownerTag); len(got) == 0 {
		t.Fatal("the control leaked nothing, so this test would prove nothing")
	}
	fmt.Println("leaked")
	if mode == "hang" {
		select {}
	}
}

func startLeakHelper(t *testing.T, mode string) (*exec.Cmd, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperLeaksABusyLoop$", "-test.v")
	cmd.Env = append(os.Environ(), helperLeakEnv+"="+mode)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	start, ok := procStart(cmd.Process.Pid)
	if !ok {
		t.Fatal("helper exited before it could be identified")
	}
	owner := strconv.Itoa(cmd.Process.Pid) + ":" + start
	t.Cleanup(func() { killOwned(owner) })

	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if sc.Text() == "leaked" {
			return cmd, owner
		}
	}
	_ = cmd.Wait()
	t.Fatal("helper never reported a leak")
	return nil, ""
}

func wantNoneOwned(t *testing.T, owner string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := ownedProcs(owner)
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d process(es) outlived the run: pids %v", len(left), left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A passing run of this package once left three busy loops on the host every
// time, a full core each, until someone killed them by hand (#105).
func TestNoProcessOutlivesAPassingRun(t *testing.T) {
	cmd, owner := startLeakHelper(t, "exit")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper failed: %v", err)
	}
	wantNoneOwned(t, owner)
}

// A run that dies before TestMain's cleanup (a -timeout panic, a SIGKILL, a
// closed terminal) must not leave the loops behind either.
func TestNoProcessOutlivesAKilledRun(t *testing.T) {
	cmd, owner := startLeakHelper(t, "hang")
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	wantNoneOwned(t, owner)
}
