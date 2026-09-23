package api

// ScanRequest is the body of POST /api/v1/scans/{module}. JobID is
// optional: supply one to control the id (the ThreatIntel backend does,
// so it can correlate with its own record), or leave it empty and the
// server generates one.
type ScanRequest struct {
	Domain   string `json:"domain"`
	TenantID string `json:"tenantId"`
	JobID    string `json:"jobId,omitempty"`
}

// ScanAccepted is the 202 body.
type ScanAccepted struct {
	JobID string `json:"jobId"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type healthResponse struct {
	Status  string          `json:"status"`
	Mode    string          `json:"mode"`
	Modules []string        `json:"modules"`
	Tools   map[string]bool `json:"tools"`
}
