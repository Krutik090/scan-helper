package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Krutik090/scan-helper/internal/jobs"
	"github.com/Krutik090/scan-helper/internal/modules/portscan"
	"github.com/Krutik090/scan-helper/internal/modules/subdomain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ScanJobDoc is the ScanJob document the ThreatIntel backend polls.
// These field names are a compatibility contract — see the plan's
// Global Constraints.
type ScanJobDoc struct {
	JobID       string             `bson:"jobId"`
	TenantID    primitive.ObjectID `bson:"tenantId"`
	Domain      string             `bson:"domain"`
	Type        string             `bson:"type"`
	Status      string             `bson:"status"`
	Count       int                `bson:"count"`
	Error       string             `bson:"error,omitempty"`
	StartedAt   *time.Time         `bson:"startedAt,omitempty"`
	CompletedAt *time.Time         `bson:"completedAt,omitempty"`
}

// ctemDoc is the slice of CTEMData this tool reads and writes. Other
// fields on the document belong to the platform and are never touched:
// every write is a targeted $set on one key.
type ctemDoc struct {
	TenantID   primitive.ObjectID    `bson:"tenantId"`
	Subdomains []subdomain.Subdomain `bson:"subdomains"`
	OpenPorts  []portscan.HostGroup  `bson:"openPorts"`
}

// scanJobType maps an API module name to the ScanJob.type value the
// backend expects. The two differ for ports/openPorts, and always have.
var scanJobType = map[string]string{
	subdomain.Name: "subdomains",
	portscan.Name:  "openPorts",
}

type MongoSink struct {
	client *mongo.Client
	db     *mongo.Database
}

// NewMongo connects and pings, so a bad URI fails at start-up rather
// than on the first finished scan.
func NewMongo(ctx context.Context, uri string) (*MongoSink, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connecting to mongo: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("pinging mongo: %w", err)
	}

	name, err := databaseName(uri)
	if err != nil {
		return nil, err
	}
	return &MongoSink{client: client, db: client.Database(name)}, nil
}

// databaseName pulls the database out of the connection string. The Go
// driver, unlike Mongoose, does not select one for you, so a URI with no
// database in its path is a configuration error rather than something to
// guess at. connstringDatabase lives in connstring.go (next step).
func databaseName(uri string) (string, error) {
	name, err := connstringDatabase(uri)
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", fmt.Errorf("mongo.uri must name a database, e.g. mongodb://host:27017/ThreatIntel")
	}
	return name, nil
}

func (m *MongoSink) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}

// Save writes the job's ScanJob document and, for a complete job, merges
// its result into CTEMData.
//
// If the result write fails (an unrecognised Result type, or a Mongo
// error inside saveSubdomains/savePorts), Save does NOT leave ScanJob
// stuck at "running" — index.js swallowed that error and reported
// "complete" for data that was never written, which is worse: the
// ThreatIntel backend would see a false success. Instead the job is
// re-marked failed, with the result-write error recorded, and that
// accurate terminal status is what gets written — then the original
// error is still returned to the caller.
func (m *MongoSink) Save(ctx context.Context, job jobs.Job) error {
	tenantID, err := primitive.ObjectIDFromHex(job.TenantID)
	if err != nil {
		return fmt.Errorf("tenantId %q is not an ObjectID: %w", job.TenantID, err)
	}

	if job.Status == jobs.StatusComplete {
		if resultErr := m.saveResult(ctx, tenantID, job); resultErr != nil {
			failed := job
			failed.Status = jobs.StatusFailed
			failed.Error = resultErr.Error()
			failed.CompletedAt = completedAtFor(failed)
			if saveErr := m.saveScanJob(ctx, tenantID, failed); saveErr != nil {
				return errors.Join(resultErr, fmt.Errorf("also writing failed ScanJob status: %w", saveErr))
			}
			return resultErr
		}
	}
	return m.saveScanJob(ctx, tenantID, job)
}

// completedAtFor returns the completedAt to write for job. A terminal job
// must carry one even if the caller built the job value directly rather
// than going through jobs.Store.SetStatus (which normally stamps it) —
// the ThreatIntel backend depends on this field being present once a job
// is done.
func completedAtFor(job jobs.Job) *time.Time {
	if job.CompletedAt != nil {
		return job.CompletedAt
	}
	if job.Status == jobs.StatusComplete || job.Status == jobs.StatusFailed {
		now := time.Now()
		return &now
	}
	return nil
}

func (m *MongoSink) saveScanJob(ctx context.Context, tenantID primitive.ObjectID, job jobs.Job) error {
	started := job.StartedAt
	doc := bson.M{
		"jobId":     job.ID,
		"tenantId":  tenantID,
		"domain":    job.Domain,
		"type":      scanJobType[job.Module],
		"status":    string(job.Status),
		"count":     job.Count,
		"startedAt": started,
	}
	if job.Error != "" {
		doc["error"] = job.Error
	}
	if completedAt := completedAtFor(job); completedAt != nil {
		doc["completedAt"] = *completedAt
	}

	_, err := m.db.Collection("ScanJob").UpdateOne(
		ctx,
		bson.M{"jobId": job.ID},
		bson.M{"$set": doc},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		return fmt.Errorf("writing ScanJob %s: %w", job.ID, err)
	}
	return nil
}

func (m *MongoSink) saveResult(ctx context.Context, tenantID primitive.ObjectID, job jobs.Job) error {
	switch res := job.Result.(type) {
	case subdomain.Result:
		return m.saveSubdomains(ctx, tenantID, job.Domain, res)
	case portscan.Result:
		return m.savePorts(ctx, tenantID, job.Domain, res)
	case nil:
		return nil
	default:
		return fmt.Errorf("job %s: unknown result type %T", job.ID, job.Result)
	}
}

func (m *MongoSink) saveSubdomains(ctx context.Context, tenantID primitive.ObjectID, domain string, res subdomain.Result) error {
	current, err := m.loadCTEM(ctx, tenantID)
	if err != nil {
		return err
	}
	merged := subdomain.Merge(current.Subdomains, res.Subdomains, domain, time.Now())
	return m.setCTEMField(ctx, tenantID, "subdomains", merged.Merged)
}

func (m *MongoSink) savePorts(ctx context.Context, tenantID primitive.ObjectID, domain string, res portscan.Result) error {
	current, err := m.loadCTEM(ctx, tenantID)
	if err != nil {
		return err
	}
	merged := portscan.Merge(current.OpenPorts, res.HostGroups, domain)
	return m.setCTEMField(ctx, tenantID, "openPorts", merged)
}

func (m *MongoSink) loadCTEM(ctx context.Context, tenantID primitive.ObjectID) (ctemDoc, error) {
	var doc ctemDoc
	err := m.db.Collection("CTEMData").FindOne(ctx, bson.M{"tenantId": tenantID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return ctemDoc{TenantID: tenantID}, nil
	}
	if err != nil {
		return ctemDoc{}, fmt.Errorf("reading CTEMData: %w", err)
	}
	return doc, nil
}

// setCTEMField writes ONE key, so nothing else on the platform's
// document is disturbed.
func (m *MongoSink) setCTEMField(ctx context.Context, tenantID primitive.ObjectID, field string, value any) error {
	_, err := m.db.Collection("CTEMData").UpdateOne(
		ctx,
		bson.M{"tenantId": tenantID},
		bson.M{"$set": bson.M{field: value}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		return fmt.Errorf("writing CTEMData.%s: %w", field, err)
	}
	return nil
}

// Targets implements portscan.TargetLister: the root domain plus the
// tenant's stored subdomains of that domain.
func (m *MongoSink) Targets(ctx context.Context, tenantID, domain string) ([]portscan.Target, error) {
	oid, err := primitive.ObjectIDFromHex(tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantId %q is not an ObjectID: %w", tenantID, err)
	}
	doc, err := m.loadCTEM(ctx, oid)
	if err != nil {
		return nil, err
	}
	return portscan.BuildTargets(domain, doc.Subdomains), nil
}
