// Package subdomain enumerates a domain's subdomains with subfinder
// (preferred) or amass (fallback), then resolves each name to an IP
// through a bounded worker pool.
package subdomain

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Krutik090/scan-helper/internal/modules"
	"github.com/Krutik090/scan-helper/internal/toolcheck"
)

// Name is the module's API name: POST /api/v1/scans/subdomains.
const Name = "subdomains"

type Config struct {
	SubfinderBin    string
	AmassBin        string
	TimeoutMinutes  int
	ResolverWorkers int
}

type Module struct {
	cfg Config
}

func New(cfg Config) *Module {
	if cfg.TimeoutMinutes <= 0 {
		cfg.TimeoutMinutes = 5
	}
	if cfg.ResolverWorkers <= 0 {
		cfg.ResolverWorkers = 50
	}
	return &Module{cfg: cfg}
}

func (m *Module) Name() string { return Name }

func (m *Module) RequiredTools() []modules.ToolRequirement {
	tools := []modules.ToolRequirement{{Name: "amass", BinPath: m.cfg.AmassBin}}
	if m.cfg.SubfinderBin != "" {
		tools = append(tools, modules.ToolRequirement{Name: "subfinder", BinPath: m.cfg.SubfinderBin})
	}
	return tools
}

// Run discovers and resolves subdomains for params.Domain. The returned
// Result holds RAW findings — merging with anything already stored is
// the storage layer's job (see the modules package doc).
func (m *Module) Run(ctx context.Context, params modules.RunParams, onProgress func(int)) (any, error) {
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(m.cfg.TimeoutMinutes)*time.Minute)
	defer cancel()

	names, preResolved, err := m.discover(runCtx, params.Domain)
	if err != nil {
		return nil, fmt.Errorf("discovering subdomains for %s: %w", params.Domain, err)
	}

	var subs []Subdomain
	if preResolved != nil {
		subs = fillMissingIPs(runCtx, preResolved, m.cfg.ResolverWorkers, realResolve)
	} else {
		subs = resolveAll(runCtx, names, m.cfg.ResolverWorkers, realResolve)
	}

	if onProgress != nil {
		onProgress(len(subs))
	}
	return Result{Domain: params.Domain, Subdomains: subs}, nil
}

// discover returns EITHER a plain name list (subfinder, or amass's txt
// fallback — these still need resolving) OR entries amass already
// resolved addresses for.
func (m *Module) discover(ctx context.Context, domain string) (names []string, preResolved []Subdomain, err error) {
	if m.cfg.SubfinderBin != "" && toolcheck.Present(m.cfg.SubfinderBin) {
		names, err = runSubfinder(ctx, m.cfg.SubfinderBin, domain)
		if err == nil && len(names) > 0 {
			return names, nil, nil
		}
		// Fall through to amass, same as the Node implementation did.
	}

	if !toolcheck.Present(m.cfg.AmassBin) {
		return nil, nil, fmt.Errorf("no usable tool: subfinder %q and amass %q are both unavailable",
			m.cfg.SubfinderBin, m.cfg.AmassBin)
	}

	tmpDir, err := os.MkdirTemp("", "scanhelper-amass-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmpDir)

	records, txtNames, err := runAmass(ctx, m.cfg.AmassBin, domain, m.cfg.TimeoutMinutes, tmpDir)
	if err != nil {
		return nil, nil, err
	}
	if len(records) > 0 {
		return nil, records, nil
	}
	return txtNames, nil, nil
}
