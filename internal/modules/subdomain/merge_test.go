package subdomain

import (
	"testing"
	"time"
)

func TestMerge_UpsertsWithoutLosingAdminOwnedData(t *testing.T) {
	now := time.Now()
	addedAt := now.Add(-24 * time.Hour)

	existing := []Subdomain{
		{Sub: "www.acme.test", IP: "10.0.0.1", Status: "Active", AssetCriticality: "High", OwnerEmail: "o@acme.test", Source: "scan"},
		{Sub: "vpn.acme.test", IP: "", Status: "Pending", Source: "client-request", AddedAt: &addedAt, AddedBy: "admin@x"},
		{Sub: "old.acme.test", IP: "10.0.0.9", Status: "Active", Source: "scan"},
		{Sub: "shop.acme.co", IP: "10.5.5.5", Status: "Active", Source: "scan"},
	}
	fresh := []Subdomain{
		{Sub: "www.acme.test", IP: "10.9.9.9"},
		{Sub: "new.acme.test", IP: "10.1.1.1"},
		{Sub: "noip.acme.test", IP: ""},
		{Sub: "new.acme.test", IP: "10.1.1.1"},
	}

	got := Merge(existing, fresh, "acme.test", now)

	if got.Created != 2 || got.Updated != 1 || got.Retained != 2 || got.Kept != 1 {
		t.Fatalf("counts: %+v", got)
	}
	if len(got.Merged) != 6 {
		t.Fatalf("merged %d entries, want 6", len(got.Merged))
	}

	byHost := map[string]Subdomain{}
	for _, s := range got.Merged {
		byHost[s.Sub] = s
	}

	if w := byHost["www.acme.test"]; w.IP != "10.9.9.9" || w.AssetCriticality != "High" || w.OwnerEmail != "o@acme.test" || w.RootDomain != "acme.test" {
		t.Errorf("www.acme.test: %+v", w)
	}
	if v := byHost["vpn.acme.test"]; v.Source != "client-request" || v.Status != "Pending" || v.IP != "" || v.AddedBy != "admin@x" {
		t.Errorf("vpn.acme.test should be retained untouched: %+v", v)
	}
	if _, ok := byHost["old.acme.test"]; !ok {
		t.Error("old.acme.test should have been retained")
	}
	if s := byHost["shop.acme.co"]; s.IP != "10.5.5.5" {
		t.Errorf("shop.acme.co must be untouched: %+v", s)
	}
	if n := byHost["new.acme.test"]; n.Source != "scan" || n.AddedAt == nil {
		t.Errorf("new.acme.test: %+v", n)
	}
	if byHost["noip.acme.test"].Status != "Inactive" {
		t.Errorf("noip.acme.test status = %q, want Inactive", byHost["noip.acme.test"].Status)
	}
}

func TestMerge_ApexAndWWWAreDistinctEntries(t *testing.T) {
	existing := []Subdomain{
		{Sub: "acme.test", AssetCriticality: "Critical", Source: "scan"},
		{Sub: "www.acme.test", AssetCriticality: "Low", Source: "scan"},
	}
	fresh := []Subdomain{{Sub: "acme.test", IP: "1.1.1.1"}, {Sub: "www.acme.test", IP: "1.1.1.2"}}

	byHost := map[string]Subdomain{}
	for _, s := range Merge(existing, fresh, "acme.test", time.Now()).Merged {
		byHost[s.Sub] = s
	}
	if byHost["acme.test"].AssetCriticality != "Critical" || byHost["www.acme.test"].AssetCriticality != "Low" {
		t.Fatalf("apex and www must not collide: %+v", byHost)
	}
}

func TestHostKeyAndDomainAttribution(t *testing.T) {
	if got := hostKey("WWW.Acme.Test."); got != "www.acme.test" {
		t.Errorf("hostKey = %q, want www.acme.test", got)
	}
	if !belongsToDomain("www.acme.test", "acme.test") {
		t.Error("www.acme.test belongs to acme.test")
	}
	if !belongsToDomain("acme.test", "www.acme.test") {
		t.Error("attribution ignores a leading www. on either side")
	}
	if belongsToDomain("acme.testing", "acme.test") {
		t.Error("acme.testing must not be attributed to acme.test")
	}
}

func TestMerge_FirstScanOnEmptyTenant(t *testing.T) {
	got := Merge(nil, []Subdomain{{Sub: "a.acme.test", IP: "1.1.1.1"}}, "acme.test", time.Now())
	if got.Created != 1 || len(got.Merged) != 1 {
		t.Fatalf("%+v", got)
	}
}
