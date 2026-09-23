// Command scan-helper runs recon modules (subdomain enumeration, port
// and service scanning) behind an HTTP API. Results are either written
// into MongoDB or returned in the API response, depending on the `mode`
// in config.yaml. See README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Krutik090/scan-helper/internal/api"
	"github.com/Krutik090/scan-helper/internal/config"
	"github.com/Krutik090/scan-helper/internal/jobs"
	"github.com/Krutik090/scan-helper/internal/modules"
	"github.com/Krutik090/scan-helper/internal/modules/portscan"
	"github.com/Krutik090/scan-helper/internal/modules/subdomain"
	"github.com/Krutik090/scan-helper/internal/storage"
	"github.com/Krutik090/scan-helper/internal/toolcheck"
)

func main() {
	configPath := flag.String("config", configPathDefault(), "path to config.yaml")
	printTools := flag.Bool("print-tools", false, "print the tools every module requires, one \"module:tool\" per line, and exit")
	flag.Parse()

	// -print-tools is what scripts/setup.sh reads to know what to
	// install, and it must run BEFORE a config file exists — a fresh box
	// has none yet, and config.Load hard-fails on a missing file. So this
	// path never touches config.Load: it builds the registry straight
	// from config.Defaults(), with every module enabled, and never
	// reaches the logger or config validation below.
	if *printTools {
		reg := buildRegistry(config.Defaults(), nil)
		fmt.Println(toolsManifest(reg))
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sink, lister, err := buildStorage(ctx, cfg, logger)
	if err != nil {
		logger.Error("storage", "error", err)
		os.Exit(1)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sink.Close(closeCtx)
	}()

	registry := buildRegistry(cfg, lister)
	warnAboutMissingTools(registry, logger)

	server := api.NewServer(api.Deps{
		Config:   cfg,
		Registry: registry,
		Jobs:     jobs.NewStore(),
		Sink:     sink,
		Logger:   logger,
	})

	if err := server.ListenAndServe(ctx); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
	logger.Info("shut down cleanly")
}

func configPathDefault() string {
	if v := os.Getenv("SCAN_HELPER_CONFIG"); v != "" {
		return v
	}
	return "./config.yaml"
}

// buildStorage returns the sink for the configured mode, plus the port
// module's target source (stored subdomains in mongo mode, the domain
// alone when nothing is stored).
func buildStorage(ctx context.Context, cfg config.Config, logger *slog.Logger) (storage.Sink, portscan.TargetLister, error) {
	if cfg.Mode != config.ModeMongo {
		logger.Info("storage mode: results are returned in the API response, no database in use")
		return storage.NewNoop(), storage.NoopTargetLister{}, nil
	}

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	sink, err := storage.NewMongo(connectCtx, cfg.Mongo.URI)
	if err != nil {
		return nil, nil, err
	}
	logger.Info("storage mode: results are written to MongoDB")
	return sink, sink, nil
}

// buildRegistry registers exactly the enabled modules. lister may be nil
// when the registry is only being inspected (-print-tools).
func buildRegistry(cfg config.Config, lister portscan.TargetLister) *modules.Registry {
	reg := modules.NewRegistry()

	if cfg.Modules.Subdomain.Enabled {
		reg.Register(subdomain.New(subdomain.Config{
			SubfinderBin:    cfg.Modules.Subdomain.SubfinderBin,
			AmassBin:        cfg.Modules.Subdomain.AmassBin,
			TimeoutMinutes:  cfg.Modules.Subdomain.TimeoutMinutes,
			ResolverWorkers: cfg.Modules.Subdomain.ResolverWorkers,
		}))
	}
	if cfg.Modules.Portscan.Enabled {
		reg.Register(portscan.New(portscan.Config{
			NmapBin:        cfg.Modules.Portscan.NmapBin,
			TimeoutMinutes: cfg.Modules.Portscan.TimeoutMinutes,
			WorkerPool:     cfg.Modules.Portscan.WorkerPool,
		}, lister))
	}
	return reg
}

// toolsManifest lists every tool every registered module requires, one
// "module:tool" per line — plain text, not JSON, so scripts/setup.sh can
// select the lines for the modules the user chose with nothing more than
// awk/grep and no jq dependency on a fresh box. Unlike Registry.Tools(),
// which dedups by tool name across modules, this iterates module by
// module so each requirement keeps its owning module's prefix.
func toolsManifest(reg *modules.Registry) string {
	var lines []string
	for _, name := range reg.Names() {
		mod, ok := reg.Get(name)
		if !ok {
			continue
		}
		for _, req := range mod.RequiredTools() {
			lines = append(lines, name+":"+req.Name)
		}
	}
	return strings.Join(lines, "\n")
}

// warnAboutMissingTools reports a missing binary at start-up rather than
// leaving it to surface as a failed scan later.
func warnAboutMissingTools(reg *modules.Registry, logger *slog.Logger) {
	for name, present := range toolcheck.Check(reg.Tools()) {
		if !present {
			logger.Warn("required tool not found — scans needing it will fail", "tool", name)
		}
	}
}
