// Package jobs tracks every scan request in memory, from the moment the
// API accepts it to the moment it finishes.
//
// This store exists regardless of storage mode: it is what makes
// GET /api/v1/jobs/{id} and progressive count updates behave identically
// whether or not MongoDB is configured. The storage mode only decides
// whether a finished job is ALSO persisted (see internal/storage).
package jobs

import (
	"sync"
	"time"
)

type Status string

// Values match ScanJob.status in Mongo — the ThreatIntel backend reads
// these strings directly.
const (
	StatusRunning  Status = "running"
	StatusComplete Status = "complete"
	StatusFailed   Status = "failed"
)

type Job struct {
	ID          string     `json:"jobId"`
	Module      string     `json:"module"`
	TenantID    string     `json:"tenantId,omitempty"`
	Domain      string     `json:"domain,omitempty"`
	Status      Status     `json:"status"`
	Count       int        `json:"count"`
	Error       string     `json:"error,omitempty"`
	Result      any        `json:"result,omitempty"`
	StartedAt   time.Time  `json:"startedAt"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

// Store is a concurrency-safe registry of jobs.
type Store struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

func NewStore() *Store {
	return &Store{jobs: make(map[string]*Job)}
}

func (s *Store) Create(job *Job) {
	if job.StartedAt.IsZero() {
		job.StartedAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = job
}

func (s *Store) Get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	return j, ok
}

// Snapshot returns a COPY, safe to read or serialise without holding the
// lock. Handlers use this rather than Get so a job mutating mid-response
// can't race the JSON encoder.
func (s *Store) Snapshot(id string) (Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return Job{}, false
	}
	return *j, true
}

func (s *Store) List(tenantID, module string) []*Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		if tenantID != "" && j.TenantID != tenantID {
			continue
		}
		if module != "" && j.Module != module {
			continue
		}
		copied := *j
		out = append(out, &copied)
	}
	return out
}

func (s *Store) SetCount(id string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		j.Count = n
	}
}

// SetStatus transitions the job and, for a terminal status, stamps
// CompletedAt.
func (s *Store) SetStatus(id string, status Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return
	}
	j.Status = status
	if status == StatusComplete || status == StatusFailed {
		now := time.Now()
		j.CompletedAt = &now
	}
}

func (s *Store) SetResult(id string, result any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		j.Result = result
	}
}

func (s *Store) SetError(id string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok && err != nil {
		j.Error = err.Error()
	}
}
