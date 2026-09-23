package storage

import (
	"context"
	"testing"

	"github.com/Krutik090/scan-helper/internal/modules/portscan"
	"github.com/Krutik090/scan-helper/internal/modules/subdomain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func oid(t *testing.T, hex string) primitive.ObjectID {
	t.Helper()
	id, err := primitive.ObjectIDFromHex(hex)
	if err != nil {
		t.Fatalf("bad ObjectID %q: %v", hex, err)
	}
	return id
}

func seedCTEM(t *testing.T, sink *MongoSink, tenant string, subs []subdomain.Subdomain) {
	t.Helper()
	_, err := sink.db.Collection("CTEMData").UpdateOne(
		context.Background(),
		bson.M{"tenantId": oid(t, tenant)},
		bson.M{"$set": bson.M{"subdomains": subs}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		t.Fatalf("seeding CTEMData: %v", err)
	}
}

func seedOpenPorts(t *testing.T, sink *MongoSink, tenant string, groups []portscan.HostGroup) {
	t.Helper()
	_, err := sink.db.Collection("CTEMData").UpdateOne(
		context.Background(),
		bson.M{"tenantId": oid(t, tenant)},
		bson.M{"$set": bson.M{"openPorts": groups}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		t.Fatalf("seeding openPorts: %v", err)
	}
}

// seedRawCTEM writes fields onto a tenant's CTEMData document exactly as
// given, with no Go struct in the way — the only way to seed rows
// carrying keys the Go structs do not name.
func seedRawCTEM(t *testing.T, sink *MongoSink, tenant string, fields bson.M) {
	t.Helper()
	_, err := sink.db.Collection("CTEMData").UpdateOne(
		context.Background(),
		bson.M{"tenantId": oid(t, tenant)},
		bson.M{"$set": fields},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		t.Fatalf("seeding raw CTEMData: %v", err)
	}
}

// rawArray reads one array field back as raw documents. A typed read
// would decode through the same structs the write used and so could never
// show a field those structs dropped.
func rawArray(t *testing.T, sink *MongoSink, tenant, field string) []bson.M {
	t.Helper()
	var doc bson.M
	if err := sink.db.Collection("CTEMData").FindOne(
		context.Background(), bson.M{"tenantId": oid(t, tenant)},
	).Decode(&doc); err != nil {
		t.Fatalf("reading raw CTEMData: %v", err)
	}
	arr, ok := doc[field].(primitive.A)
	if !ok {
		t.Fatalf("CTEMData.%s is %T, want an array: %+v", field, doc[field], doc[field])
	}
	out := make([]bson.M, 0, len(arr))
	for _, el := range arr {
		m, ok := el.(bson.M)
		if !ok {
			t.Fatalf("CTEMData.%s element is %T, want a document", field, el)
		}
		out = append(out, m)
	}
	return out
}

func readScanJob(t *testing.T, sink *MongoSink, jobID string) ScanJobDoc {
	t.Helper()
	var doc ScanJobDoc
	if err := sink.db.Collection("ScanJob").FindOne(
		context.Background(), bson.M{"jobId": jobID},
	).Decode(&doc); err != nil {
		t.Fatalf("reading ScanJob %s: %v", jobID, err)
	}
	return doc
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func readCTEM(t *testing.T, sink *MongoSink, tenant string) []subdomain.Subdomain {
	t.Helper()
	var doc ctemDoc
	if err := sink.db.Collection("CTEMData").FindOne(context.Background(), bson.M{"tenantId": oid(t, tenant)}).Decode(&doc); err != nil {
		t.Fatalf("reading CTEMData: %v", err)
	}
	return doc.Subdomains
}

func readOpenPorts(t *testing.T, sink *MongoSink, tenant string) []portscan.HostGroup {
	t.Helper()
	var doc ctemDoc
	if err := sink.db.Collection("CTEMData").FindOne(context.Background(), bson.M{"tenantId": oid(t, tenant)}).Decode(&doc); err != nil {
		t.Fatalf("reading CTEMData: %v", err)
	}
	return doc.OpenPorts
}
