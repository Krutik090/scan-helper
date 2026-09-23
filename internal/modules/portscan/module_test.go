package portscan

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Krutik090/scan-helper/internal/modules"
	"github.com/Krutik090/scan-helper/internal/modules/subdomain"
)

func TestBuildTargets_RootPlusItsSubdomainsOnly(t *testing.T) {
	subs := []subdomain.Subdomain{
		{Sub: "www.acme.test", IP: "1.1.1.1"},
		{Sub: "api.acme.test", IP: ""},
		{Sub: "shop.acme.co", IP: "2.2.2.2"}, // different root domain
		{Sub: "acme.test", IP: "3.3.3.3"},    // the root itself, already first
	}
	targets := BuildTargets("acme.test", subs)

	if len(targets) != 3 {
		t.Fatalf("got %d targets, want root + 2 in-domain subdomains: %+v", len(targets), targets)
	}
	if targets[0].Host != "acme.test" {
		t.Errorf("the root domain should lead the target list, got %q", targets[0].Host)
	}
	for _, tg := range targets {
		if strings.HasSuffix(tg.Host, "acme.co") {
			t.Errorf("another root domain leaked into the target list: %q", tg.Host)
		}
	}
}

type fakeLister struct{ targets []Target }

func (f fakeLister) Targets(context.Context, string, string) ([]Target, error) { return f.targets, nil }

func TestScanTargets_BoundedConcurrencyAndProgress(t *testing.T) {
	const workers = 3
	var inFlight, peak int32

	scan := func(_ context.Context, target string) ([]Port, string, error) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		if target == "quiet.acme.test" {
			return nil, "9.9.9.9", nil // host up, nothing open
		}
		return []Port{{Port: 443, Protocol: "tcp", State: "Open"}}, "9.9.9.9", nil
	}

	targets := []Target{
		{Host: "acme.test"}, {Host: "a.acme.test"}, {Host: "b.acme.test"},
		{Host: "c.acme.test"}, {Host: "quiet.acme.test"}, {Host: "d.acme.test"},
	}

	var progressCalls int32
	groups := scanTargets(context.Background(), targets, "acme.test", workers, scan,
		func(int) { atomic.AddInt32(&progressCalls, 1) })

	if peak > workers {
		t.Fatalf("peak concurrency %d exceeded the %d-worker bound", peak, workers)
	}
	if len(groups) != 5 {
		t.Fatalf("got %d host groups, want 5 (the host with no open ports is omitted): %+v", len(groups), groups)
	}
	for _, g := range groups {
		if g.RootDomain != "acme.test" {
			t.Errorf("host group missing its root domain stamp: %+v", g)
		}
		if g.Host == "quiet.acme.test" {
			t.Error("a host with no open ports must not produce a group")
		}
	}
	if progressCalls == 0 {
		t.Error("progress should be reported as hosts complete")
	}
}

func TestModule_Metadata(t *testing.T) {
	m := New(Config{NmapBin: "/usr/bin/nmap"}, fakeLister{})
	if m.Name() != "ports" {
		t.Errorf("Name = %q, want ports", m.Name())
	}
	tools := m.RequiredTools()
	if len(tools) != 1 || tools[0].Name != "nmap" || tools[0].BinPath != "/usr/bin/nmap" {
		t.Fatalf("RequiredTools = %+v", tools)
	}
}

func TestModule_RunFailsClearlyWithoutNmap(t *testing.T) {
	m := New(Config{NmapBin: "/nonexistent/nmap", TimeoutMinutes: 1, WorkerPool: 2},
		fakeLister{targets: []Target{{Host: "acme.test"}}})

	_, err := m.Run(context.Background(), modules.RunParams{JobID: "j", Domain: "acme.test"}, nil)
	if err == nil || !strings.Contains(err.Error(), "nmap") {
		t.Fatalf("expected a clear nmap-missing error, got %v", err)
	}
}
