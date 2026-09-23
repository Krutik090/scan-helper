package main

import (
	"strings"
	"testing"

	"github.com/Krutik090/scan-helper/internal/config"
)

func TestBuildRegistry_RespectsEnabledFlags(t *testing.T) {
	both := buildRegistry(config.Config{Modules: config.ModulesConfig{
		Subdomain: config.SubdomainModuleConfig{Enabled: true, AmassBin: "/usr/bin/amass"},
		Portscan:  config.PortscanModuleConfig{Enabled: true, NmapBin: "/usr/bin/nmap"},
	}}, nil)
	if got := both.Names(); len(got) != 2 {
		t.Fatalf("both enabled: got %v", got)
	}

	portsOnly := buildRegistry(config.Config{Modules: config.ModulesConfig{
		Subdomain: config.SubdomainModuleConfig{Enabled: false},
		Portscan:  config.PortscanModuleConfig{Enabled: true, NmapBin: "/usr/bin/nmap"},
	}}, nil)
	if got := portsOnly.Names(); len(got) != 1 || got[0] != "ports" {
		t.Fatalf("subdomain disabled: got %v", got)
	}
}

// TestToolsManifest_ListsEveryRequiredTool replaces the brief's JSON-based
// TestToolsJSON_ListsEveryRequiredTool: -print-tools now emits plain
// "module:tool" lines (see toolsManifest's doc comment for why), so this
// asserts the actual line shape instead of JSON containment.
func TestToolsManifest_ListsEveryRequiredTool(t *testing.T) {
	reg := buildRegistry(config.Config{Modules: config.ModulesConfig{
		Subdomain: config.SubdomainModuleConfig{Enabled: true, AmassBin: "/usr/bin/amass", SubfinderBin: "/opt/subfinder"},
		Portscan:  config.PortscanModuleConfig{Enabled: true, NmapBin: "/usr/bin/nmap"},
	}}, nil)

	out := toolsManifest(reg)

	for _, want := range []string{"subdomains:amass", "subdomains:subfinder", "ports:nmap"} {
		if !strings.Contains(out, want) {
			t.Errorf("tools manifest is missing %q: %s", want, out)
		}
	}

	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			t.Errorf("line %q does not match the module:tool shape", line)
		}
	}
}
