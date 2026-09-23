package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_AppliesDefaultsForUnsetFields(t *testing.T) {
	cfg, err := Load(write(t, "server:\n  api_key: secret\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 4001 {
		t.Errorf("port = %d, want default 4001", cfg.Server.Port)
	}
	if cfg.Mode != ModeMongo {
		t.Errorf("mode = %q, want default %q", cfg.Mode, ModeMongo)
	}
	if cfg.Modules.Subdomain.ResolverWorkers != 50 {
		t.Errorf("resolver_workers = %d, want default 50", cfg.Modules.Subdomain.ResolverWorkers)
	}
	if cfg.Modules.Portscan.WorkerPool != 5 {
		t.Errorf("worker_pool = %d, want default 5", cfg.Modules.Portscan.WorkerPool)
	}
	if !cfg.Modules.Subdomain.Enabled || !cfg.Modules.Portscan.Enabled {
		t.Error("modules should default to enabled")
	}
}

func TestLoad_FileOverridesDefaults(t *testing.T) {
	cfg, err := Load(write(t, `
server:
  port: 9000
  api_key: secret
mode: api_response
modules:
  portscan:
    worker_pool: 12
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9000 || cfg.Mode != ModeAPIResponse || cfg.Modules.Portscan.WorkerPool != 12 {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	// Untouched fields must still hold their defaults.
	if cfg.Modules.Subdomain.ResolverWorkers != 50 {
		t.Errorf("resolver_workers = %d, want 50", cfg.Modules.Subdomain.ResolverWorkers)
	}
}

func TestValidate_RefusesUnsafeOrImpossibleConfigs(t *testing.T) {
	cases := map[string]string{
		"no api key":             "mode: api_response\n",
		"mongo mode without uri": "server:\n  api_key: k\nmode: mongo\nmongo:\n  uri: \"\"\n",
		"unknown mode":           "server:\n  api_key: k\nmode: sideways\n",
		"all modules disabled":   "server:\n  api_key: k\nmode: api_response\nmodules:\n  subdomain:\n    enabled: false\n  portscan:\n    enabled: false\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

// TestDefaults_ToolBinariesAreBareNamesResolvedOnPATH guards against
// reintroducing a distro-specific absolute path (e.g. Kali's
// /usr/lib/amass/amass, which doesn't exist on the Ubuntu box setup.sh
// targets — apt puts it at /usr/bin/amass). A bare command name is
// resolved through PATH at run time by toolcheck.Present, so it works
// regardless of which distro's package layout installed the binary, and
// it's also what makes -print-tools able to report every tool without
// requiring a config file first.
func TestDefaults_ToolBinariesAreBareNamesResolvedOnPATH(t *testing.T) {
	d := Defaults()
	cases := map[string]string{
		"modules.subdomain.subfinder_bin": d.Modules.Subdomain.SubfinderBin,
		"modules.subdomain.amass_bin":     d.Modules.Subdomain.AmassBin,
		"modules.portscan.nmap_bin":       d.Modules.Portscan.NmapBin,
	}
	want := map[string]string{
		"modules.subdomain.subfinder_bin": "subfinder",
		"modules.subdomain.amass_bin":     "amass",
		"modules.portscan.nmap_bin":       "nmap",
	}
	for field, got := range cases {
		if got != want[field] {
			t.Errorf("%s = %q, want bare command name %q", field, got, want[field])
		}
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("%s = %q looks like a path, not a bare command name", field, got)
		}
	}
}
