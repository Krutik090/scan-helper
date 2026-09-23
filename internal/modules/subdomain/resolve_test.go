package subdomain

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// countingResolver records the highest number of lookups in flight at
// once, so the test can prove the pool is actually bounded.
func countingResolver(peak *int32, answer func(string) string) resolveFunc {
	var inFlight int32
	return func(_ context.Context, name string) string {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			old := atomic.LoadInt32(peak)
			if n <= old || atomic.CompareAndSwapInt32(peak, old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return answer(name)
	}
}

func TestResolveAll_RespectsWorkerBound(t *testing.T) {
	const workers = 4
	var peak int32
	resolve := countingResolver(&peak, func(string) string { return "1.2.3.4" })

	names := make([]string, 24)
	for i := range names {
		names[i] = "host.example.test"
	}

	got := resolveAll(context.Background(), names, workers, resolve)

	if len(got) != len(names) {
		t.Fatalf("got %d results, want %d", len(got), len(names))
	}
	if peak > workers {
		t.Fatalf("peak concurrency %d exceeded the %d-worker bound", peak, workers)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency %d suggests the work never ran in parallel", peak)
	}
}

func TestResolveAll_StatusFollowsResolution(t *testing.T) {
	resolve := func(_ context.Context, name string) string {
		if name == "resolves.test" {
			return "10.0.0.1"
		}
		return ""
	}
	byName := map[string]Subdomain{}
	for _, s := range resolveAll(context.Background(), []string{"resolves.test", "missing.test"}, 2, resolve) {
		byName[s.Sub] = s
	}
	if got := byName["resolves.test"]; got.IP != "10.0.0.1" || got.Status != "Active" {
		t.Errorf("resolves.test: %+v", got)
	}
	if got := byName["missing.test"]; got.IP != "" || got.Status != "Inactive" {
		t.Errorf("missing.test: %+v", got)
	}
}

func TestResolveAll_StopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	names := make([]string, 100)
	for i := range names {
		names[i] = "slow.test"
	}
	done := make(chan struct{})
	go func() {
		resolveAll(ctx, names, 2, func(context.Context, string) string { return "" })
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("resolveAll did not return promptly on a cancelled context")
	}
}

func TestFillMissingIPs_OnlyResolvesGaps(t *testing.T) {
	var lookups int32
	resolve := func(_ context.Context, name string) string {
		atomic.AddInt32(&lookups, 1)
		return "9.9.9.9"
	}
	in := []Subdomain{
		{Sub: "has-ip.test", IP: "1.1.1.1"},
		{Sub: "no-ip.test"},
	}
	out := fillMissingIPs(context.Background(), in, 4, resolve)

	if lookups != 1 {
		t.Fatalf("resolved %d names, want only the one missing an IP", lookups)
	}
	byName := map[string]Subdomain{}
	for _, s := range out {
		byName[s.Sub] = s
	}
	if byName["has-ip.test"].IP != "1.1.1.1" || byName["has-ip.test"].Status != "Active" {
		t.Errorf("has-ip.test: %+v", byName["has-ip.test"])
	}
	if byName["no-ip.test"].IP != "9.9.9.9" || byName["no-ip.test"].Status != "Active" {
		t.Errorf("no-ip.test: %+v", byName["no-ip.test"])
	}
}
