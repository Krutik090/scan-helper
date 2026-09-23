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
	r.Register(fakeModule{name: "zulu", tools: []ToolRequirement{}})
	r.Register(fakeModule{name: "alpha", tools: []ToolRequirement{}})
	r.Register(fakeModule{name: "mike", tools: []ToolRequirement{}})
	r.Register(fakeModule{name: "bravo", tools: []ToolRequirement{}})
	r.Register(fakeModule{name: "yankee", tools: []ToolRequirement{}})

	if _, ok := r.Get("alpha"); !ok {
		t.Fatal("alpha should be registered")
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("unregistered module should not resolve")
	}
	names := r.Names()
	if len(names) != 5 || names[0] != "zulu" || names[1] != "alpha" || names[2] != "mike" || names[3] != "bravo" || names[4] != "yankee" {
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
