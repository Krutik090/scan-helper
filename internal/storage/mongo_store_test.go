package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Krutik090/scan-helper/internal/jobs"
	"github.com/Krutik090/scan-helper/internal/modules/portscan"
	"github.com/Krutik090/scan-helper/internal/modules/subdomain"
	"go.mongodb.org/mongo-driver/bson"
)

// These run only when a MongoDB is reachable. Set SCAN_HELPER_TEST_MONGO_URI
// to a throwaway database, e.g.
//
//	SCAN_HELPER_TEST_MONGO_URI=mongodb://localhost:27017/scanhelper_test go test ./internal/storage/
func testMongo(t *testing.T) *MongoSink {
	t.Helper()
	uri := os.Getenv("SCAN_HELPER_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("SCAN_HELPER_TEST_MONGO_URI not set — skipping Mongo integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sink, err := NewMongo(ctx, uri)
	if err != nil {
		t.Fatalf("connecting to test Mongo: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sink.db.Collection("CTEMData").DeleteMany(context.Background(), bson.M{})
		_, _ = sink.db.Collection("ScanJob").DeleteMany(context.Background(), bson.M{})
		_ = sink.Close(context.Background())
	})
	return sink
}

func TestMongoSink_SubdomainsUpsertPreservesAdminData(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196ad"

	// Something a client requested and an admin added — the scanner will
	// never rediscover it, and a rescan must not delete it.
	seedCTEM(t, sink, tenant, []subdomain.Subdomain{
		{Sub: "vpn.acme.test", Status: "Pending", Source: "client-request"},
		{Sub: "www.acme.test", IP: "1.1.1.1", Status: "Active", AssetCriticality: "High", Source: "scan"},
	})

	job := jobs.Job{
		ID: "job-1", Module: "subdomains", TenantID: tenant, Domain: "acme.test",
		Status: jobs.StatusComplete, Count: 2,
		Result: subdomain.Result{Domain: "acme.test", Subdomains: []subdomain.Subdomain{
			{Sub: "www.acme.test", IP: "9.9.9.9", Status: "Active"},
			{Sub: "new.acme.test", IP: "8.8.8.8", Status: "Active"},
		}},
	}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	stored := readCTEM(t, sink, tenant)
	byHost := map[string]subdomain.Subdomain{}
	for _, s := range stored {
		byHost[s.Sub] = s
	}
	if len(stored) != 3 {
		t.Fatalf("want 3 entries (refreshed + retained + created), got %d: %+v", len(stored), stored)
	}
	if byHost["www.acme.test"].IP != "9.9.9.9" || byHost["www.acme.test"].AssetCriticality != "High" {
		t.Errorf("www.acme.test: %+v", byHost["www.acme.test"])
	}
	if byHost["vpn.acme.test"].Source != "client-request" {
		t.Errorf("the client-requested entry must survive a rescan: %+v", byHost["vpn.acme.test"])
	}

	// And the ScanJob document the ThreatIntel backend polls.
	var doc ScanJobDoc
	if err := sink.db.Collection("ScanJob").FindOne(ctx, bson.M{"jobId": "job-1"}).Decode(&doc); err != nil {
		t.Fatalf("reading ScanJob: %v", err)
	}
	if doc.Type != "subdomains" || doc.Status != "complete" || doc.Count != 2 {
		t.Fatalf("ScanJob document: %+v", doc)
	}
	if doc.CompletedAt == nil {
		t.Error("a complete job must stamp completedAt")
	}
}

func TestMongoSink_PortsReplaceWithinDomain(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196ae"

	seedOpenPorts(t, sink, tenant, []portscan.HostGroup{
		{Host: "www.acme.test", Ports: []portscan.Port{{Port: 22, State: "Open"}}},
		{Host: "shop.acme.co", Ports: []portscan.Port{{Port: 80, State: "Open"}}},
	})

	job := jobs.Job{
		ID: "job-2", Module: "ports", TenantID: tenant, Domain: "acme.test",
		Status: jobs.StatusComplete, Count: 1,
		Result: portscan.Result{Domain: "acme.test", HostGroups: []portscan.HostGroup{
			{Host: "www.acme.test", Ports: []portscan.Port{{Port: 443, State: "Open"}}, RootDomain: "acme.test"},
		}},
	}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	stored := readOpenPorts(t, sink, tenant)
	byHost := map[string][]portscan.Port{}
	for _, g := range stored {
		byHost[g.Host] = g.Ports
	}
	if len(stored) != 2 {
		t.Fatalf("want this domain replaced + the other domain kept, got %+v", stored)
	}
	if len(byHost["www.acme.test"]) != 1 || byHost["www.acme.test"][0].Port != 443 {
		t.Errorf("www.acme.test should hold only this run's ports: %+v", byHost["www.acme.test"])
	}
	if _, kept := byHost["shop.acme.co"]; !kept {
		t.Error("shop.acme.co belongs to another domain and must be untouched")
	}
}

func TestMongoSink_FailedJobRecordsTheError(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()

	job := jobs.Job{
		ID: "job-3", Module: "ports", TenantID: "6a7dc0f5458d051280d196af", Domain: "acme.test",
		Status: jobs.StatusFailed, Error: "nmap timed out",
	}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var doc ScanJobDoc
	if err := sink.db.Collection("ScanJob").FindOne(ctx, bson.M{"jobId": "job-3"}).Decode(&doc); err != nil {
		t.Fatalf("reading ScanJob: %v", err)
	}
	if doc.Status != "failed" || doc.Error != "nmap timed out" {
		t.Fatalf("ScanJob document: %+v", doc)
	}
	// ScanJob.type must be the Mongo-side name, not the API module name.
	if doc.Type != "openPorts" {
		t.Fatalf("type = %q, want openPorts (the value the backend reads)", doc.Type)
	}
}

func TestMongoSink_TargetsComeFromStoredSubdomains(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196b0"

	seedCTEM(t, sink, tenant, []subdomain.Subdomain{
		{Sub: "www.acme.test", IP: "1.1.1.1"},
		{Sub: "shop.acme.co", IP: "2.2.2.2"},
	})

	targets, err := sink.Targets(ctx, tenant, "acme.test")
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("want the root plus its one in-domain subdomain, got %+v", targets)
	}
}

// unrecognisedResult is neither subdomain.Result nor portscan.Result, so
// saveResult hits its default branch.
type unrecognisedResult struct {
	Foo string
}

func TestMongoSink_ResultWriteFailureStillRecordsTerminalStatus(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()

	job := jobs.Job{
		ID: "job-4", Module: "ports", TenantID: "6a7dc0f5458d051280d196b1", Domain: "acme.test",
		Status: jobs.StatusComplete, Count: 1,
		Result: unrecognisedResult{Foo: "bar"},
	}
	if err := sink.Save(ctx, job); err == nil {
		t.Fatal("Save: want an error for an unrecognised result type, got nil")
	}

	var doc ScanJobDoc
	if err := sink.db.Collection("ScanJob").FindOne(ctx, bson.M{"jobId": "job-4"}).Decode(&doc); err != nil {
		t.Fatalf("reading ScanJob: %v", err)
	}
	if doc.Status != "failed" {
		t.Errorf("status = %q, want failed — a result-write failure must not leave ScanJob stuck at running", doc.Status)
	}
	if doc.Error == "" {
		t.Error("want a non-empty error field recording why the save failed")
	}
	if doc.CompletedAt == nil {
		t.Error("want completedAt stamped even though the job never reached a clean complete")
	}
}
