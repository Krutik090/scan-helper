package modules

import (
	"context"
	"testing"
)

type fakeModule struct {
	name  string
	tools []ToolRequirement
}

func (f fakeModule) Name() string                     { return f.name }
func (f fakeModule) RequiredTools() []ToolRequirement { return f.tools }
func (f fakeModule) Run(context.Context, RunParams, func(int)) (any, error) {
	return nil, nil
}

func TestRegistry_RegisterGetNamesAreStable(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeModule{name: "subdomains", tools: []ToolRequirement{{Name: "amass", BinPath: "/usr/bin/amass"}}})
	r.Register(fakeModule{name: "ports", tools: []ToolRequirement{{Name: "nmap", BinPath: "/usr/bin/nmap"}}})

	if _, ok := r.Get("ports"); !ok {
		t.Fatal("ports should be registered")
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("unregistered module should not resolve")
	}
	names := r.Names()
	if len(names) != 2 || names[0] != "subdomains" || names[1] != "ports" {
		t.Fatalf("Names() should preserve registration order, got %v", names)
	}
}

func TestRegistry_ToolsAggregatesAcrossModules(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeModule{name: "a", tools: []ToolRequirement{{Name: "nmap", BinPath: "/usr/bin/nmap"}}})
	r.Register(fakeModule{name: "b", tools: []ToolRequirement{{Name: "nmap", BinPath: "/usr/bin/nmap"}, {Name: "amass", BinPath: "/usr/bin/amass"}}})

	tools := r.Tools()
	if len(tools) != 2 {
		t.Fatalf("duplicate tools should collapse, got %v", tools)
	}
}
