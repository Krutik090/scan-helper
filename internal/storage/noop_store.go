package storage

import (
	"context"

	"github.com/Krutik090/scan-helper/internal/jobs"
)

type noopSink struct{}

// NewNoop returns the api_response-mode sink: results are served from
// the job store, so there is nothing to persist.
func NewNoop() Sink { return noopSink{} }

func (noopSink) Start(context.Context, jobs.Job) error    { return nil }
func (noopSink) Progress(context.Context, jobs.Job) error { return nil }
func (noopSink) Save(context.Context, jobs.Job) error     { return nil }
func (noopSink) Close(context.Context) error              { return nil }
