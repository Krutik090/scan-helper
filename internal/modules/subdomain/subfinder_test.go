package subdomain

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestRunSubfinder_OverLongLineDoesNotHangTheScan covers the deadlock
// this reader used to have: the scanner stops on a line over its 1MB
// cap, but the tool is still running and still writing, so abandoning
// the pipe leaves it to fill — the tool blocks on its next write and
// cmd.Wait blocks with it, until the module timeout kills a scan that
// had already produced good names.
//
// The fake tool below prints one usable name, then a line well over the
// cap, then several megabytes more — far more than any pipe buffer
// holds. Without the drain this call never returns.
func TestRunSubfinder_OverLongLineDoesNotHangTheScan(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh in this environment; cannot stand up a fake scanner")
	}

	script := filepath.Join(t.TempDir(), "fake-subfinder")
	body := "#!" + sh + "\n" +
		"echo good.acme.test\n" +
		"head -c 1200000 /dev/zero | tr '\\0' x\n" +
		"echo\n" +
		`awk 'BEGIN{for(i=0;i<200000;i++)print "filler" i ".acme.test"}'` + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	type result struct {
		names []string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		names, err := runSubfinder(context.Background(), script, "acme.test")
		done <- result{names, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("an over-long line should degrade, not fail: %v", got.err)
		}
		// Everything before the over-long line is kept; the rest of the
		// output is drained away, which is the cost of not hanging.
		if len(got.names) != 1 || got.names[0] != "good.acme.test" {
			t.Errorf("names = %v, want the one name read before the over-long line", got.names)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("runSubfinder did not return: the unread pipe blocked the tool, and cmd.Wait blocked on it")
	}
}
