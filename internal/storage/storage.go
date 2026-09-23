// Package storage decides what happens to a finished job's result.
//
// This is the whole of the mode toggle. In mongo mode the Mongo sink
// merges the result into the collections the ThreatIntel backend reads;
// in api_response mode the no-op sink does nothing, because the result
// already lives in the in-memory job store that serves
// GET /api/v1/jobs/{id}.
//
// The sink is also where merging with previously stored state happens —
// each module exports a pure Merge function, and only the sink knows
// whether prior state exists to merge with.
package storage

import (
	"context"

	"github.com/Krutik090/scan-helper/internal/jobs"
	"github.com/Krutik090/scan-helper/internal/modules/portscan"
)

// Sink is the storage mode's three-point view of a job's life. The
// external ThreatIntel backend polls the ScanJob row by jobId, so a row
// has to exist for the MINUTES a scan takes, not only once it finishes:
// index.js wrote status "running" with startedAt the moment a scan
// began, and pushed count in as it progressed ("so frontend polling
// shows progress"). Without Start, a poller sees nothing at all until
// the end, and a process that restarts mid-scan loses the job entirely
// rather than leaving a diagnosable "running" row behind.
//
// Start and Progress are best-effort: the caller logs a failure and
// carries on scanning. Losing progress reporting is not worth failing a
// working scan over. Save is the terminal write and its failure is
// recorded on the job as before.
type Sink interface {
	// Start upserts the job's row as running, before the module runs.
	Start(ctx context.Context, job jobs.Job) error
	// Progress updates the running row's count as findings accumulate.
	Progress(ctx context.Context, job jobs.Job) error
	// Save is the terminal write: final status, and the result itself.
	Save(ctx context.Context, job jobs.Job) error
	Close(ctx context.Context) error
}

// NoopTargetLister is the api_response-mode target source: nothing is
// stored, so a port scan covers the requested domain and nothing else.
type NoopTargetLister struct{}

func (NoopTargetLister) Targets(_ context.Context, _, domain string) ([]portscan.Target, error) {
	return []portscan.Target{{Host: domain}}, nil
}
