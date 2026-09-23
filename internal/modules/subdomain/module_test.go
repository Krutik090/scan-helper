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
