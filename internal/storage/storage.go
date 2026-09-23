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

type Sink interface {
	Save(ctx context.Context, job jobs.Job) error
	Close(ctx context.Context) error
}

// NoopTargetLister is the api_response-mode target source: nothing is
// stored, so a port scan covers the requested domain and nothing else.
type NoopTargetLister struct{}

func (NoopTargetLister) Targets(_ context.Context, _, domain string) ([]portscan.Target, error) {
	return []portscan.Target{{Host: domain}}, nil
}
