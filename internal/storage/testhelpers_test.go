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
