package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Krutik090/scan-helper/internal/config"
	"github.com/Krutik090/scan-helper/internal/jobs"
	"github.com/Krutik090/scan-helper/internal/modules"
	"github.com/Krutik090/scan-helper/internal/toolcheck"
	"github.com/go-chi/chi/v5"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:  "ok",
		Mode:    string(s.deps.Config.Mode),
		Modules: s.deps.Registry.Names(),
		Tools:   toolcheck.Check(s.deps.Registry.Tools()),
	})
}

// handleScan accepts a scan, starts it in the background, and returns
// its job id. Long scans must not hold an HTTP connection open, so the
// result is collected through GET /api/v1/jobs/{id}.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	moduleName := chi.URLParam(r, "module")
	module, ok := s.deps.Registry.Get(moduleName)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: fmt.Sprintf("unknown module %q", moduleName)})
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "body must be JSON"})
		return
	}
	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "domain is required"})
		return
	}
	if req.TenantID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "tenantId is required"})
		return
	}

	jobID := req.JobID
	if jobID == "" {
		jobID = fmt.Sprintf("%s-%d", moduleName, time.Now().UnixNano())
	}

	job := &jobs.Job{
		ID:       jobID,
		Module:   moduleName,
		TenantID: req.TenantID,
		Domain:   req.Domain,
		Status:   jobs.StatusRunning,
	}

	// CreateIfAbsent is atomic: an already-known job id is idempotent —
	// return the existing job rather than starting a second scan over
	// the same ground. A separate exists-check then Create would leave a
	// window where two concurrent posts of the same id both pass the
	// check and both start a scan.
	if !s.deps.Jobs.CreateIfAbsent(job) {
		writeJSON(w, http.StatusAccepted, ScanAccepted{JobID: jobID})
		return
	}

	go s.runJob(module, jobID, modules.RunParams{JobID: jobID, TenantID: req.TenantID, Domain: req.Domain})

	writeJSON(w, http.StatusAccepted, ScanAccepted{JobID: jobID})
}

// runJob executes a module and records the outcome. It runs on its own
// goroutine with a background context, so a client disconnecting does
// not abort a scan already under way. A panicking module must not take
// the whole process — and every other in-flight job — down with it, so
// a recover here converts it into a failed job instead.
func (s *Server) runJob(module modules.Module, jobID string, params modules.RunParams) {
	logger := s.deps.Logger.With("job", jobID, "module", module.Name(), "domain", params.Domain)
	logger.Info("scan started")

	defer func() {
		if rec := recover(); rec != nil {
			logger.Error("scan panicked", "panic", rec)
			s.deps.Jobs.SetError(jobID, fmt.Errorf("module panicked: %v", rec))
			s.deps.Jobs.SetStatus(jobID, jobs.StatusFailed)
			s.persist(jobID, logger)
		}
	}()

	// Announce the job as running BEFORE the module starts, so the
	// external backend polling by jobId sees a row for the minutes a scan
	// takes — and so a process killed mid-scan leaves a diagnosable
	// "running" row rather than no row at all.
	s.announce(jobID, logger, s.deps.Sink.Start, "recording the job as running failed")

	result, err := module.Run(context.Background(), params, func(count int) {
		s.deps.Jobs.SetCount(jobID, count)
		s.announce(jobID, logger, s.deps.Sink.Progress, "recording scan progress failed")
	})
	if err != nil {
		logger.Error("scan failed", "error", err)
		s.deps.Jobs.SetError(jobID, err)
		s.deps.Jobs.SetStatus(jobID, jobs.StatusFailed)
		s.persist(jobID, logger)
		return
	}

	s.deps.Jobs.SetResult(jobID, result)
	s.deps.Jobs.SetStatus(jobID, jobs.StatusComplete)
	logger.Info("scan complete")
	s.persist(jobID, logger)
}

// announce runs one of the sink's non-terminal lifecycle writes (Start,
// Progress). Unlike persist, a failure here is LOGGED AND DROPPED: it
// never touches the job's status and never aborts the scan. Losing
// progress reporting is not a reason to fail a scan that is working —
// the terminal Save still has to succeed, and still reports if it
// doesn't.
func (s *Server) announce(jobID string, logger loggerLike, write func(context.Context, jobs.Job) error, what string) {
	snapshot, ok := s.deps.Jobs.Snapshot(jobID)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := write(ctx, snapshot); err != nil {
		logger.Error(what, "error", err)
	}
}

// persist hands the finished job to the configured sink. A storage
// failure is recorded on the job rather than lost, but never panics the
// server — the scan itself already succeeded.
func (s *Server) persist(jobID string, logger loggerLike) {
	snapshot, ok := s.deps.Jobs.Snapshot(jobID)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.deps.Sink.Save(ctx, snapshot); err != nil {
		logger.Error("saving results failed", "error", err)
		s.deps.Jobs.SetError(jobID, err)
		s.deps.Jobs.SetStatus(jobID, jobs.StatusFailed)
	}
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	snapshot, ok := s.deps.Jobs.Snapshot(chi.URLParam(r, "id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no such job"})
		return
	}
	writeJSON(w, http.StatusOK, s.viewJob(snapshot))
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	list := s.deps.Jobs.List(r.URL.Query().Get("tenantId"), r.URL.Query().Get("module"))
	views := make([]jobs.Job, 0, len(list))
	for _, j := range list {
		views = append(views, s.viewJob(*j))
	}
	writeJSON(w, http.StatusOK, views)
}

// viewJob strips the inline result in mongo mode: there, the data has
// been written to the caller's database and echoing it back would just
// duplicate a potentially very large payload.
func (s *Server) viewJob(job jobs.Job) jobs.Job {
	if s.deps.Config.Mode != config.ModeAPIResponse {
		job.Result = nil
	}
	return job
}

// loggerLike keeps persist testable without dragging in slog's concrete
// type.
type loggerLike interface {
	Error(msg string, args ...any)
}
