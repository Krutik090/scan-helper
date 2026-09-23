package portscan

import "testing"

func TestMerge_ReplacesThisDomainAndKeepsOthers(t *testing.T) {
	existing := []HostGroup{
		{Host: "www.acme.test", Ports: []Port{{Port: 443}}},
		{Host: "old.acme.test", Ports: []Port{{Port: 22}}},
		{Host: "shop.acme.co", Ports: []Port{{Port: 80}}},
	}
	fresh := []HostGroup{
		{Host: "www.acme.test", Ports: []Port{{Port: 443}, {Port: 8443}}, RootDomain: "acme.test"},
	}

	merged := Merge(existing, fresh, "acme.test")

	byHost := map[string][]Port{}
	for _, hg := range merged {
		byHost[hg.Host] = hg.Ports
	}
	if len(merged) != 2 {
		t.Fatalf("got %d host groups, want 2: %+v", len(merged), merged)
	}
	if len(byHost["www.acme.test"]) != 2 {
		t.Errorf("www.acme.test should carry this run's 2 ports: %+v", byHost["www.acme.test"])
	}
	// old.acme.test was in scope and returned nothing this run: it genuinely
	// has no open ports now, so a stale entry would be a lie.
	if _, stale := byHost["old.acme.test"]; stale {
		t.Error("old.acme.test must not survive as a stale result")
	}
	if _, kept := byHost["shop.acme.co"]; !kept {
		t.Error("shop.acme.co belongs to another root domain and must be untouched")
	}
}

func TestMerge_FirstScanOnEmptyTenant(t *testing.T) {
	fresh := []HostGroup{{Host: "acme.test", Ports: []Port{{Port: 80}}}}
	if got := Merge(nil, fresh, "acme.test"); len(got) != 1 {
		t.Fatalf("got %+v, want the one fresh group", got)
	}
}

func TestBelongsToDomain(t *testing.T) {
	if !belongsToDomain("www.acme.test", "acme.test") || !belongsToDomain("acme.test", "acme.test") {
		t.Error("a host and its www. form both belong to the domain")
	}
	if belongsToDomain("acme.testing", "acme.test") {
		t.Error("acme.testing must not be attributed to acme.test")
	}
}
