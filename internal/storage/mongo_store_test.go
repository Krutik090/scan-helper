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
	"go.mongodb.org/mongo-driver/bson/primitive"
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

// TestMongoSink_UnknownStoredFieldsSurviveAMerge is the regression test
// for the typed-decode data loss: a merge decodes the stored rows into Go
// structs and writes the WHOLE array back, so any key the structs do not
// name would be dropped from every row that merely passes through —
// `_id` included, along with anything the ThreatIntel platform has added
// to a row since. The rows are seeded as raw BSON and read back as raw
// BSON, because a typed read would hide exactly the loss being tested.
func TestMongoSink_UnknownStoredFieldsSurviveAMerge(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196c0"

	rescannedID := primitive.NewObjectID()
	untouchedID := primitive.NewObjectID()
	otherDomainID := primitive.NewObjectID()

	seedRawCTEM(t, sink, tenant, bson.M{"subdomains": bson.A{
		// This one the scan finds again: Merge rebuilds it from the scan
		// result, so it only keeps its _id if Merge copies Extra across.
		bson.M{
			"_id": rescannedID, "sub": "www.acme.test", "ip": "1.1.1.1", "status": "Active",
			"assetCriticality": "High", "platformNote": "keep me",
		},
		// This one the scan does not return: retained, must pass through whole.
		bson.M{
			"_id": untouchedID, "sub": "vpn.acme.test", "ip": "", "status": "Pending",
			"source": "client-request", "platformNote": "keep me",
		},
		// Another root domain entirely: kept, must pass through whole.
		bson.M{
			"_id": otherDomainID, "sub": "shop.acme.co", "ip": "2.2.2.2", "status": "Active",
			"platformNote": "keep me",
		},
	}})

	job := jobs.Job{
		ID: "job-extra-subs", Module: "subdomains", TenantID: tenant, Domain: "acme.test",
		Status: jobs.StatusComplete, Count: 1,
		Result: subdomain.Result{Domain: "acme.test", Subdomains: []subdomain.Subdomain{
			{Sub: "www.acme.test", IP: "9.9.9.9", Status: "Active"},
		}},
	}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rows := rawArray(t, sink, tenant, "subdomains")
	bySub := map[string]bson.M{}
	for _, r := range rows {
		bySub[asString(r["sub"])] = r
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows back, got %d: %+v", len(rows), rows)
	}

	for _, tc := range []struct {
		sub  string
		id   primitive.ObjectID
		what string
	}{
		{"vpn.acme.test", untouchedID, "a row the scan did not return (retained)"},
		{"shop.acme.co", otherDomainID, "a row of another root domain (kept)"},
		{"www.acme.test", rescannedID, "a row the scan found again (updated)"},
	} {
		row, ok := bySub[tc.sub]
		if !ok {
			t.Errorf("%s vanished from the array: %s", tc.sub, tc.what)
			continue
		}
		if got, _ := row["_id"].(primitive.ObjectID); got != tc.id {
			t.Errorf("%s (%s): _id = %v, want %v — the platform addresses rows by _id", tc.sub, tc.what, row["_id"], tc.id)
		}
		if row["platformNote"] != "keep me" {
			t.Errorf("%s (%s): platformNote = %v, want %q — an unknown field must survive the round trip",
				tc.sub, tc.what, row["platformNote"], "keep me")
		}
	}
	// The merge must still have done its actual job.
	if bySub["www.acme.test"]["ip"] != "9.9.9.9" {
		t.Errorf("the rescanned row should carry the fresh ip: %+v", bySub["www.acme.test"])
	}
	if bySub["www.acme.test"]["assetCriticality"] != "High" {
		t.Errorf("the rescanned row must keep its admin-owned criticality: %+v", bySub["www.acme.test"])
	}
}

func TestMongoSink_UnknownStoredFieldsSurviveAPortMerge(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196c1"

	keptID := primitive.NewObjectID()
	keptPortID := primitive.NewObjectID()

	seedRawCTEM(t, sink, tenant, bson.M{"openPorts": bson.A{
		// Belongs to acme.test, so this run replaces it — nothing to preserve.
		bson.M{"_id": primitive.NewObjectID(), "host": "www.acme.test", "ports": bson.A{
			bson.M{"port": 22, "protocol": "tcp", "service": "ssh", "state": "Open", "risk": "Low"},
		}},
		// Another root domain: kept untouched, down to its nested port row.
		bson.M{
			"_id": keptID, "host": "shop.acme.co", "ip": "2.2.2.2", "platformNote": "keep me",
			"ports": bson.A{
				bson.M{
					"_id": keptPortID, "port": 80, "protocol": "tcp", "service": "http",
					"state": "Open", "risk": "Low", "platformNote": "keep me",
				},
			},
		},
	}})

	job := jobs.Job{
		ID: "job-extra-ports", Module: "ports", TenantID: tenant, Domain: "acme.test",
		Status: jobs.StatusComplete, Count: 1,
		Result: portscan.Result{Domain: "acme.test", HostGroups: []portscan.HostGroup{
			{Host: "www.acme.test", Ports: []portscan.Port{{Port: 443, State: "Open", Risk: "Low"}}, RootDomain: "acme.test"},
		}},
	}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rows := rawArray(t, sink, tenant, "openPorts")
	var kept bson.M
	for _, r := range rows {
		if asString(r["host"]) == "shop.acme.co" {
			kept = r
		}
	}
	if kept == nil {
		t.Fatalf("the other domain's host group vanished: %+v", rows)
	}
	if got, _ := kept["_id"].(primitive.ObjectID); got != keptID {
		t.Errorf("kept host group _id = %v, want %v", kept["_id"], keptID)
	}
	if kept["platformNote"] != "keep me" {
		t.Errorf("kept host group platformNote = %v, want %q", kept["platformNote"], "keep me")
	}

	ports, _ := kept["ports"].(primitive.A)
	if len(ports) != 1 {
		t.Fatalf("kept host group should still hold its one port: %+v", kept["ports"])
	}
	port, _ := ports[0].(bson.M)
	if got, _ := port["_id"].(primitive.ObjectID); got != keptPortID {
		t.Errorf("kept port _id = %v, want %v — nested rows are re-encoded too", port["_id"], keptPortID)
	}
	if port["platformNote"] != "keep me" {
		t.Errorf("kept port platformNote = %v, want %q", port["platformNote"], "keep me")
	}
}

// TestMongoSink_NewRowsCarryThePlatformDefaults pins the starting values
// index.js gave every row it created. The keys have to be PRESENT on a
// new row — the platform reads them — and an updated or retained row has
// to keep whatever is stored instead.
func TestMongoSink_NewRowsCarryThePlatformDefaults(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196c4"

	thirty := 30
	seedCTEM(t, sink, tenant, []subdomain.Subdomain{
		{Sub: "www.acme.test", IP: "1.1.1.1", Status: "Active",
			AssetCriticality: "High", SSLGrade: "A+", SSLDaysRemaining: &thirty},
	})

	job := jobs.Job{
		ID: "job-defaults", Module: "subdomains", TenantID: tenant, Domain: "acme.test",
		Status: jobs.StatusComplete, Count: 2,
		Result: subdomain.Result{Domain: "acme.test", Subdomains: []subdomain.Subdomain{
			{Sub: "www.acme.test", IP: "9.9.9.9"}, // updated
			{Sub: "new.acme.test", IP: "8.8.8.8"}, // created
		}},
	}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rows := rawArray(t, sink, tenant, "subdomains")
	bySub := map[string]bson.M{}
	for _, r := range rows {
		bySub[asString(r["sub"])] = r
	}

	created := bySub["new.acme.test"]
	if created["assetCriticality"] != "Low" {
		t.Errorf("a new row's assetCriticality = %v, want %q", created["assetCriticality"], "Low")
	}
	if created["sslGrade"] != "N/A" {
		t.Errorf("a new row's sslGrade = %v, want %q", created["sslGrade"], "N/A")
	}
	if _, present := created["sslDaysRemaining"]; !present {
		t.Errorf("a new row must carry sslDaysRemaining (as null): %+v", created)
	} else if created["sslDaysRemaining"] != nil {
		t.Errorf("a new row's sslDaysRemaining = %v, want null", created["sslDaysRemaining"])
	}

	updated := bySub["www.acme.test"]
	if updated["assetCriticality"] != "High" || updated["sslGrade"] != "A+" {
		t.Errorf("an updated row must keep the stored values, got %+v", updated)
	}
	if got, _ := updated["sslDaysRemaining"].(int32); got != 30 {
		t.Errorf("an updated row's sslDaysRemaining = %v, want 30", updated["sslDaysRemaining"])
	}
}

func TestMongoSink_PortRowsAlwaysCarryIPAndVersion(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196c5"

	job := jobs.Job{
		ID: "job-port-keys", Module: "ports", TenantID: tenant, Domain: "acme.test",
		Status: jobs.StatusComplete, Count: 1,
		Result: portscan.Result{Domain: "acme.test", HostGroups: []portscan.HostGroup{
			// Neither an address nor a version came back from this scan;
			// index.js still emitted both keys, as ''.
			{Host: "www.acme.test", Ports: []portscan.Port{
				{Port: 22, Protocol: "tcp", Service: "ssh", State: "Open", Risk: "Low"},
			}, RootDomain: "acme.test"},
		}},
	}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rows := rawArray(t, sink, tenant, "openPorts")
	if len(rows) != 1 {
		t.Fatalf("want one host group, got %+v", rows)
	}
	if got, present := rows[0]["ip"]; !present || got != "" {
		t.Errorf("host group ip = %v (present=%v), want an empty string", got, present)
	}
	ports, _ := rows[0]["ports"].(primitive.A)
	if len(ports) != 1 {
		t.Fatalf("want one port, got %+v", rows[0]["ports"])
	}
	port, _ := ports[0].(bson.M)
	if got, present := port["version"]; !present || got != "" {
		t.Errorf("port version = %v (present=%v), want an empty string", got, present)
	}
}

// TestMongoSink_JobIsVisibleWhileItRuns covers the lifecycle the external
// backend polls: a ScanJob row exists as "running" from the moment the
// scan starts, its count moves while the scan is under way, and only
// then does it go terminal.
func TestMongoSink_JobIsVisibleWhileItRuns(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()
	tenant := "6a7dc0f5458d051280d196c2"

	job := jobs.Job{
		ID: "job-lifecycle", Module: "ports", TenantID: tenant, Domain: "acme.test",
		Status: jobs.StatusRunning, StartedAt: time.Now(),
	}

	if err := sink.Start(ctx, job); err != nil {
		t.Fatalf("Start: %v", err)
	}
	running := readScanJob(t, sink, "job-lifecycle")
	if running.Status != string(jobs.StatusRunning) {
		t.Fatalf("status = %q, want running — the backend polls this row for the whole scan", running.Status)
	}
	if running.StartedAt == nil || running.StartedAt.IsZero() {
		t.Error("a running job must carry startedAt")
	}
	if running.Type != "openPorts" {
		t.Errorf("type = %q, want openPorts", running.Type)
	}
	if running.CompletedAt != nil {
		t.Error("a running job must not carry completedAt yet")
	}
	if running.CreatedAt == nil || running.UpdatedAt == nil {
		t.Fatalf("both Mongoose timestamps must be written: %+v", running)
	}
	createdAt := *running.CreatedAt

	// Progress moves the count on the same row.
	job.Count = 7
	if err := sink.Progress(ctx, job); err != nil {
		t.Fatalf("Progress: %v", err)
	}
	progressed := readScanJob(t, sink, "job-lifecycle")
	if progressed.Count != 7 {
		t.Errorf("count = %d, want 7 — progress must be visible before the scan ends", progressed.Count)
	}
	if progressed.Status != string(jobs.StatusRunning) {
		t.Errorf("status = %q, want running — Progress must not change it", progressed.Status)
	}

	// And Save then takes it terminal, without moving createdAt.
	job.Count = 9
	job.Status = jobs.StatusComplete
	job.Result = portscan.Result{Domain: "acme.test"}
	if err := sink.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}
	done := readScanJob(t, sink, "job-lifecycle")
	if done.Status != string(jobs.StatusComplete) || done.Count != 9 {
		t.Fatalf("terminal row = %+v", done)
	}
	if done.CompletedAt == nil {
		t.Error("a complete job must stamp completedAt")
	}
	if done.CreatedAt == nil || !done.CreatedAt.Equal(createdAt) {
		t.Errorf("createdAt moved: %v then %v — it is written on insert only", createdAt, done.CreatedAt)
	}
	if done.UpdatedAt == nil || done.UpdatedAt.Before(createdAt) {
		t.Errorf("updatedAt = %v, want a stamp from this write", done.UpdatedAt)
	}
}

// TestMongoSink_ProgressWithoutStartCreatesNothing pins the deliberate
// non-upsert: a count-only row would read to a poller as a job with no
// status at all.
func TestMongoSink_ProgressWithoutStartCreatesNothing(t *testing.T) {
	sink := testMongo(t)
	ctx := context.Background()

	job := jobs.Job{ID: "job-no-start", Module: "ports", TenantID: "6a7dc0f5458d051280d196c3", Count: 4}
	if err := sink.Progress(ctx, job); err != nil {
		t.Fatalf("Progress on an absent row must be a quiet no-op: %v", err)
	}
	n, err := sink.db.Collection("ScanJob").CountDocuments(ctx, bson.M{"jobId": "job-no-start"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("Progress created %d row(s); it must never create one", n)
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
