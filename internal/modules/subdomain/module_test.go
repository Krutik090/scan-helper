package subdomain

import (
	"context"
	"strings"
	"testing"

	"github.com/Krutik090/scan-helper/internal/modules"
)

func TestModule_MetadataAndToolRequirements(t *testing.T) {
	m := New(Config{SubfinderBin: "/opt/subfinder", AmassBin: "/usr/bin/amass"})
	if m.Name() != "subdomains" {
		t.Errorf("Name = %q, want subdomains", m.Name())
	}

	tools := m.RequiredTools()
	if len(tools) != 2 {
		t.Fatalf("want amass and subfinder, got %+v", tools)
	}

	// With no subfinder configured, amass is the only requirement.
	only := New(Config{AmassBin: "/usr/bin/amass"}).RequiredTools()
	if len(only) != 1 || only[0].Name != "amass" {
		t.Fatalf("without subfinder configured the only tool is amass, got %+v", only)
	}
}

func TestModule_RunFailsClearlyWhenNoToolIsAvailable(t *testing.T) {
	m := New(Config{
		SubfinderBin:    "/nonexistent/subfinder",
		AmassBin:        "/nonexistent/amass",
		TimeoutMinutes:  1,
		ResolverWorkers: 4,
	})

	_, err := m.Run(context.Background(), modules.RunParams{JobID: "j1", Domain: "acme.test"}, nil)
	if err == nil {
		t.Fatal("expected an error when neither subfinder nor amass exists")
	}
	if !strings.Contains(err.Error(), "acme.test") {
		t.Errorf("error should name the domain it failed on, got %q", err)
	}
}

// TestModule_AcceptsBareAmassBinResolvedOnPATH guards the presence check
// itself: the module used to gate on a local os.Stat-based fileExists,
// which fails for a bare command name (no path separator) even when
// that name resolves fine on PATH — amass_bin's config default is now
// exactly such a bare name ("amass"). "true" stands in for amass here:
// it is a bare name virtually guaranteed to be on PATH. Run "true" as
// amass exits 0 with no output files, which amass.go treats as a clean,
// empty success — so if the presence gate still rejected bare names,
// Run would fail with "no usable tool"; instead it must succeed with an
// empty result, proving the gate accepted the PATH-resolved name.
func TestModule_AcceptsBareAmassBinResolvedOnPATH(t *testing.T) {
	m := New(Config{AmassBin: "true", TimeoutMinutes: 1, ResolverWorkers: 4})

	res, err := m.Run(context.Background(), modules.RunParams{JobID: "j1", Domain: "acme.test"}, nil)
	if err != nil {
		t.Fatalf("presence check rejected the bare, PATH-resolvable amass_bin %q: %v", "true", err)
	}
	result, ok := res.(Result)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	if result.Domain != "acme.test" {
		t.Errorf("Domain = %q, want acme.test", result.Domain)
	}
}
