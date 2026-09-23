// Package portscan scans a domain and its known subdomains for open
// ports and services with nmap.
package portscan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Krutik090/scan-helper/internal/modules"
	"github.com/Krutik090/scan-helper/internal/modules/subdomain"
)

// Name is the module's API name: POST /api/v1/scans/ports.
const Name = "ports"

type Config struct {
	NmapBin        string
	TimeoutMinutes int
	WorkerPool     int
}

// Target is one host to scan.
type Target struct {
	Host string
	IP   string
}

// TargetLister supplies the hosts in scope for a scan. In mongo mode
// this reads the tenant's stored subdomains; in api_response mode, where
// nothing is stored, it yields just the domain itself.
type TargetLister interface {
	Targets(ctx context.Context, tenantID, domain string) ([]Target, error)
}

type Module struct {
	cfg    Config
	lister TargetLister
}

func New(cfg Config, lister TargetLister) *Module {
	if cfg.TimeoutMinutes <= 0 {
		cfg.TimeoutMinutes = 10
	}
	if cfg.WorkerPool <= 0 {
		cfg.WorkerPool = 5
	}
	return &Module{cfg: cfg, lister: lister}
}

func (m *Module) Name() string { return Name }

func (m *Module) RequiredTools() []modules.ToolRequirement {
	return []modules.ToolRequirement{{Name: "nmap", BinPath: m.cfg.NmapBin}}
}

// BuildTargets is the scoping rule: the root domain first, then its own
// subdomains, deduplicated. Hosts belonging to another root domain are
// excluded, so scanning one domain never touches another's results.
//
// Dedup uses a plain lowercase/trailing-dot-trimmed key rather than
// normHost: normHost also strips a leading "www.", which is right for
// treating www.example.com and example.com as the same asset identity
// in merge.go, but wrong here — "www.example.com" is a distinct
// hostname nmap must scan on its own, not a stand-in for the root that
// should be dropped as a duplicate.
func BuildTargets(domain string, subs []subdomain.Subdomain) []Target {
	root := scopeKey(domain)
	seen := map[string]struct{}{root: {}}
	targets := []Target{{Host: domain}}

	for _, s := range subs {
		if s.Sub == "" || !belongsToDomain(s.Sub, domain) {
			continue
		}
		key := scopeKey(s.Sub)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, Target{Host: s.Sub, IP: s.IP})
	}
	return targets
}

// scopeKey normalizes a host for BuildTargets' own-entry dedup: lowercase
// and trailing-dot trimmed, but — unlike normHost — no "www." stripping,
// since www.example.com and example.com are different scan targets here.
func scopeKey(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func (m *Module) Run(ctx context.Context, params modules.RunParams, onProgress func(int)) (any, error) {
	if !fileExists(m.cfg.NmapBin) {
		return nil, fmt.Errorf("nmap is not available at %q", m.cfg.NmapBin)
	}

	targets, err := m.lister.Targets(ctx, params.TenantID, params.Domain)
	if err != nil {
		return nil, fmt.Errorf("listing targets for %s: %w", params.Domain, err)
	}
	if len(targets) == 0 {
		return Result{Domain: params.Domain}, nil
	}

	perHostTimeout := time.Duration(m.cfg.TimeoutMinutes) * time.Minute
	scan := func(ctx context.Context, target string) ([]Port, string, error) {
		return runNmap(ctx, m.cfg.NmapBin, target, perHostTimeout)
	}

	groups, err := scanTargets(ctx, targets, params.Domain, m.cfg.WorkerPool, scan, onProgress)
	if err != nil {
		return nil, err
	}
	return Result{Domain: params.Domain, HostGroups: groups}, nil
}

// scanTargets runs `scan` across targets through a bounded pool of
// `workers` goroutines. Workers pull individually, so one slow host
// delays only itself — a fixed-size sequential batch would make every
// host in a batch wait for its slowest member. Progress is reported as
// each host finishes, so a poller sees continuous movement rather than
// jumps of one batch.
//
// A host with no open ports produces no group: it genuinely has nothing
// open, and an empty group would only add noise. A host that errors is
// likewise skipped from the results, but its failure is counted: if
// every target errored, that is not "nothing open" but a total scan
// failure (a crashing nmap binary, missing permissions, and so on), and
// is reported as an error rather than as an empty success — the storage
// layer's Merge REPLACES a domain's host groups with whatever this
// returns, so an empty success here would silently delete every
// previously-known open port for the domain. Partial failure — some
// hosts unreachable, others fine — is normal for a real scan and stays
// a success with whatever data came back.
func scanTargets(
	ctx context.Context,
	targets []Target,
	domain string,
	workers int,
	scan scanFunc,
	onProgress func(int),
) ([]HostGroup, error) {
	if workers < 1 {
		workers = 1
	}
	root := normHost(domain)

	in := make(chan Target)
	out := make(chan HostGroup, len(targets))

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failCount int
	var lastErr error

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range in {
				ports, ip, err := scan(ctx, t.Host)
				if err != nil {
					mu.Lock()
					failCount++
					lastErr = err
					mu.Unlock()
					continue
				}
				if len(ports) == 0 {
					continue
				}
				if ip == "" {
					ip = t.IP
				}
				out <- HostGroup{Host: t.Host, IP: ip, Ports: ports, RootDomain: root}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, t := range targets {
			select {
			case in <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	groups := make([]HostGroup, 0, len(targets))
	total := 0
	for g := range out {
		groups = append(groups, g)
		total += len(g.Ports)
		if onProgress != nil {
			onProgress(total)
		}
	}

	if len(targets) > 0 && failCount == len(targets) {
		return nil, fmt.Errorf("all %d targets failed scanning %s: %w", failCount, domain, lastErr)
	}
	return groups, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
