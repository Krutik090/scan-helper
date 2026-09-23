package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Krutik090/scan-helper/internal/config"
	"github.com/Krutik090/scan-helper/internal/jobs"
	"github.com/Krutik090/scan-helper/internal/modules"
	"github.com/Krutik090/scan-helper/internal/storage"
)

type stubModule struct {
	name   string
	result any
	err    error
	delay  time.Duration
}

func (s stubModule) Name() string { return s.name }
func (s stubModule) RequiredTools() []modules.ToolRequirement {
	return []modules.ToolRequirement{{Name: "sh", BinPath: "sh"}}
}
func (s stubModule) Run(ctx context.Context, _ modules.RunParams, onProgress func(int)) (any, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if onProgress != nil {
		onProgress(3)
	}
	return s.result, s.err
}

// recordingSink counts the sink's lifecycle calls and can be told to
// fail the non-terminal ones.
type recordingSink struct {
	mu                  sync.Mutex
	starts              int
	progress            int
	saves               int
	failStartAndProgres bool
}

func (r *recordingSink) Start(context.Context, jobs.Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts++
	if r.failStartAndProgres {
		return errors.New("mongo is down")
	}
	return nil
}

func (r *recordingSink) Progress(context.Context, jobs.Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.progress++
	if r.failStartAndProgres {
		return errors.New("mongo is down")
	}
	return nil
}

func (r *recordingSink) Save(context.Context, jobs.Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.saves++
	return nil
}

func (r *recordingSink) Close(context.Context) error { return nil }

func (r *recordingSink) counts() (int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.starts, r.progress, r.saves
}

func testServer(t *testing.T, mode config.Mode, mod modules.Module) *Server {
	t.Helper()
	return testServerWithSink(t, mode, mod, storage.NewNoop())
}

func testServerWithSink(t *testing.T, mode config.Mode, mod modules.Module, sink storage.Sink) *Server {
	t.Helper()
	reg := modules.NewRegistry()
	reg.Register(mod)

	return NewServer(Deps{
		Config: config.Config{
			Server: config.ServerConfig{Port: 0, APIKey: "test-key"},
			Mode:   mode,
		},
		Registry: reg,
		Jobs:     jobs.NewStore(),
		Sink:     sink,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func post(t *testing.T, srv *Server, path, key string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestAuth_RejectsMissingOrWrongKey(t *testing.T) {
	srv := testServer(t, config.ModeAPIResponse, stubModule{name: "subdomains"})

	for name, key := range map[string]string{"missing": "", "wrong": "nope"} {
		t.Run(name, func(t *testing.T) {
			rec := post(t, srv, "/api/v1/scans/subdomains", key, ScanRequest{Domain: "acme.test", TenantID: "t1"})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
		})
	}
}

func TestHealth_NeedsNoKeyAndReportsToolsAndMode(t *testing.T) {
	srv := testServer(t, config.ModeMongo, stubModule{name: "subdomains"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Status string          `json:"status"`
		Mode   string          `json:"mode"`
		Tools  map[string]bool `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Mode != "mongo" {
		t.Fatalf("body = %+v", body)
	}
	if !body.Tools["sh"] {
		t.Errorf("health should report tool presence, got %+v", body.Tools)
	}
}

func TestScan_AcceptsAndCompletesTheJob(t *testing.T) {
	srv := testServer(t, config.ModeAPIResponse, stubModule{
		name:   "subdomains",
		result: map[string]any{"domain": "acme.test"},
	})

	rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: "acme.test", TenantID: "t1"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	var accepted ScanAccepted
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.JobID == "" {
		t.Fatal("a jobId should be returned")
	}

	job := waitForTerminal(t, srv, accepted.JobID)
	if job.Status != string(jobs.StatusComplete) {
		t.Fatalf("job = %+v", job)
	}
	if job.Count != 3 {
		t.Errorf("progress callback should have set count=3, got %d", job.Count)
	}
	// api_response mode embeds the result.
	if job.Result == nil {
		t.Error("api_response mode must return the result inline")
	}
}

func TestScan_MongoModeOmitsInlineResult(t *testing.T) {
	srv := testServer(t, config.ModeMongo, stubModule{
		name:   "subdomains",
		result: map[string]any{"domain": "acme.test"},
	})
	rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: "acme.test", TenantID: "6a7dc0f5458d051280d196ad"})
	var accepted ScanAccepted
	_ = json.Unmarshal(rec.Body.Bytes(), &accepted)

	job := waitForTerminal(t, srv, accepted.JobID)
	if job.Result != nil {
		t.Fatalf("mongo mode must not echo the result — it is in the database: %+v", job.Result)
	}
}

func TestScan_UnknownModuleAndBadRequest(t *testing.T) {
	srv := testServer(t, config.ModeAPIResponse, stubModule{name: "subdomains"})

	if rec := post(t, srv, "/api/v1/scans/nonsense", "test-key", ScanRequest{Domain: "a.test", TenantID: "t"}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown module status = %d, want 404", rec.Code)
	}
	if rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{TenantID: "t"}); rec.Code != http.StatusBadRequest {
		t.Errorf("missing domain status = %d, want 400", rec.Code)
	}
}

// TestScan_RejectsADomainThatIsNotAHostname is the API-boundary half of
// the argv-injection gate: these strings would reach nmap's or
// subfinder's command line, and nmap honours options anywhere on it.
func TestScan_RejectsADomainThatIsNotAHostname(t *testing.T) {
	srv := testServer(t, config.ModeAPIResponse, stubModule{
		name:   "subdomains",
		result: map[string]any{"domain": "acme.test"},
	})

	for name, domain := range map[string]string{
		"a leading hyphen":  "-oN /etc/cron.d/x",
		"an nmap option":    "--script=http-put",
		"a space":           "acme.test evil.test",
		"a slash":           "acme.test/../etc/passwd",
		"a shell separator": "acme.test;id",
	} {
		t.Run(name, func(t *testing.T) {
			rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: domain, TenantID: "t1"})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for domain %q: %s", rec.Code, domain, rec.Body)
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte("hostname")) {
				t.Errorf("the 400 should say what is wrong, got %s", rec.Body)
			}
		})
	}

	t.Run("a normal hostname is accepted", func(t *testing.T) {
		rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: "www.acme.test", TenantID: "t1"})
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
		}
	})
}

func TestScan_FailingModuleMarksJobFailed(t *testing.T) {
	srv := testServer(t, config.ModeAPIResponse, stubModule{name: "subdomains", err: context.DeadlineExceeded})

	rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: "acme.test", TenantID: "t1"})
	var accepted ScanAccepted
	_ = json.Unmarshal(rec.Body.Bytes(), &accepted)

	job := waitForTerminal(t, srv, accepted.JobID)
	if job.Status != string(jobs.StatusFailed) || job.Error == "" {
		t.Fatalf("job = %+v", job)
	}
}

func TestScan_ReportsTheJobAsRunningAndThenProgresses(t *testing.T) {
	sink := &recordingSink{}
	srv := testServerWithSink(t, config.ModeMongo, stubModule{
		name:   "subdomains",
		result: map[string]any{"domain": "acme.test"},
	}, sink)

	rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: "acme.test", TenantID: "6a7dc0f5458d051280d196ad"})
	var accepted ScanAccepted
	_ = json.Unmarshal(rec.Body.Bytes(), &accepted)
	waitForTerminal(t, srv, accepted.JobID)

	starts, progress, saves := sink.counts()
	if starts != 1 {
		t.Errorf("Start called %d times, want 1 — the backend polls for a running row", starts)
	}
	if progress != 1 {
		t.Errorf("Progress called %d times, want 1 (the stub reports once)", progress)
	}
	if saves != 1 {
		t.Errorf("Save called %d times, want 1", saves)
	}
}

func TestScan_LifecycleWriteFailureDoesNotAbortTheScan(t *testing.T) {
	sink := &recordingSink{failStartAndProgres: true}
	srv := testServerWithSink(t, config.ModeMongo, stubModule{
		name:   "subdomains",
		result: map[string]any{"domain": "acme.test"},
	}, sink)

	rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: "acme.test", TenantID: "6a7dc0f5458d051280d196ad"})
	var accepted ScanAccepted
	_ = json.Unmarshal(rec.Body.Bytes(), &accepted)

	job := waitForTerminal(t, srv, accepted.JobID)
	if job.Status != string(jobs.StatusComplete) {
		t.Fatalf("a failed progress write must not fail a working scan: %+v", job)
	}
	if job.Error != "" {
		t.Errorf("a failed progress write must not be recorded on the job: %q", job.Error)
	}
	if _, _, saves := sink.counts(); saves != 1 {
		t.Errorf("the terminal Save must still run: %d", saves)
	}
}

func TestJobs_UnknownIDIs404(t *testing.T) {
	srv := testServer(t, config.ModeAPIResponse, stubModule{name: "subdomains"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/nope", nil)
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

type panicModule struct{ name string }

func (p panicModule) Name() string { return p.name }
func (p panicModule) RequiredTools() []modules.ToolRequirement {
	return []modules.ToolRequirement{{Name: "sh", BinPath: "sh"}}
}
func (p panicModule) Run(context.Context, modules.RunParams, func(int)) (any, error) {
	panic("boom: nil pointer somewhere in the module")
}

func TestScan_PanickingModuleDoesNotCrashTheServer(t *testing.T) {
	srv := testServer(t, config.ModeAPIResponse, panicModule{name: "subdomains"})

	rec := post(t, srv, "/api/v1/scans/subdomains", "test-key", ScanRequest{Domain: "acme.test", TenantID: "t1"})
	var accepted ScanAccepted
	_ = json.Unmarshal(rec.Body.Bytes(), &accepted)

	job := waitForTerminal(t, srv, accepted.JobID)
	if job.Status != string(jobs.StatusFailed) || job.Error == "" {
		t.Fatalf("job = %+v", job)
	}

	// The server must keep serving after a module panic.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	healthRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(healthRec, req)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health after panic = %d, want 200", healthRec.Code)
	}
}

type jobView struct {
	JobID  string `json:"jobId"`
	Status string `json:"status"`
	Count  int    `json:"count"`
	Error  string `json:"error"`
	Result any    `json:"result"`
}

func waitForTerminal(t *testing.T, srv *Server, id string) jobView {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+id, nil)
		req.Header.Set("X-API-Key", "test-key")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET /jobs/%s = %d", id, rec.Code)
		}
		var view jobView
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if view.Status == string(jobs.StatusComplete) || view.Status == string(jobs.StatusFailed) {
			return view
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s never reached a terminal status", id)
	return jobView{}
}
