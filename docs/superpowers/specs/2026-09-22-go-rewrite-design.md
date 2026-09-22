# scan-helper: Go rewrite — design

Status: approved by user, pending implementation plan.
Replaces the existing single-file `index.js` (Node/Express/Mongoose) in place, in this same repo.

## 1. Why

`scan-helper` is a small service that runs on the Kali box and performs the actual
recon work (subdomain enumeration, port/service scanning) that the ThreatIntel platform
requests over HTTP. Today it is one 600-line `index.js`: no module boundaries, fixed
sequential-batch concurrency, regex-scraped `nmap` text output, and exactly one way to
return data (write straight into the shared MongoDB the ThreatIntel backend also reads).

Three things are changing:

1. **Language & structure.** Rewritten in Go, split into per-module packages behind one
   `Module` interface, so a third module (planned, not built here) is "add a package +
   a registry line," not "edit a 600-line file."
2. **Concurrency & parsing quality.** Real bounded worker pools instead of fixed
   sequential batches; `nmap`'s structured XML output instead of regex over its
   human-readable text.
3. **Deployability.** A config-driven toggle between "write to MongoDB" (today's only
   behavior) and "return the result in the API response" (new), plus a setup script so
   this can be handed to someone else's box, not just this one.

## 2. Scope

In scope: the two existing modules (subdomain enumeration, port/service scanning),
rewritten with feature parity plus the improvements below; the HTTP API; the mode
toggle; the setup script; README + API docs; tests; QA on WSL Ubuntu.

Out of scope (explicitly, for this spec): any third module; changes to the ThreatIntel
backend (`threatIntel-backend`) — it keeps calling the same host, same Mongo, same
collection shapes, unmodified; a UI for this tool; distributing it as more than one
process.

## 3. Approach

Single Go binary. Each module is an internal package implementing:

```go
type Module interface {
    Name() string
    RequiredTools() []ToolRequirement
    Run(ctx context.Context, params RunParams) (Result, error)
}
```

Module code never imports `net/http` or the Mongo driver — it takes typed params and a
context, returns a typed result or an error. The HTTP layer and the storage layer are
both just callers of this interface. This is what makes "more modules later" cheap, and
it's what makes each module unit-testable without a server or a database.

**Rejected alternative:** multiple processes (an API/coordinator process plus separate
worker processes per module) communicating over a queue. This is a real architecture for
a service that scales across machines; `scan-helper` runs on one box, against local CLI
tools (`nmap`, `subfinder`, `amass`) that themselves must run locally — there is nothing
for a second process or a broker to do here. Rejected as unwarranted complexity.

## 4. Package layout

```
scan-helper/
  cmd/scan-helper/main.go        # load config, build the module registry, start the server
  internal/
    config/
      config.go                  # Config struct, YAML loader, env var overrides, validation
    api/
      server.go                  # http.Server, middleware chain, graceful shutdown
      router.go                  # route table (chi)
      middleware.go               # auth (X-API-Key), request logging, panic recovery
      handlers_scan.go            # POST /api/v1/scans/{module} — generic, dispatches via registry
      handlers_jobs.go            # GET /api/v1/jobs/{id}, GET /api/v1/jobs
      handlers_health.go          # GET /api/v1/health
      dto.go                      # request/response structs (versioned under /v1)
    jobs/
      job.go                      # Job, Status (queued|running|complete|failed), typed Result
      store.go                    # in-memory JobStore — ALWAYS used, regardless of mode
                                   # (mode only decides whether storage/ ALSO persists to Mongo)
    storage/
      storage.go                  # Sink interface: Save(ctx, job Job) error
      mongo_store.go              # writes ScanJob + CTEMData — same collection/field
                                   # names & upsert-merge semantics as today; see §7
      noop_store.go                # api_response mode: no-op (result already lives in the
                                   # in-memory Job, which the jobs handler serves)
    modules/
      subdomain/
        module.go                  # Module impl: orchestrates subfinder→amass→resolve→merge
        subfinder.go                 # subprocess invocation, streaming line parse
        amass.go                     # subprocess invocation, streaming JSON-lines parse, txt fallback
        resolve.go                   # bounded worker-pool DNS resolution
        merge.go                     # hash-map upsert merge (ported from the Node fix, §7)
        types.go                     # Subdomain, Result
      portscan/
        module.go                    # Module impl: target scoping → worker pool → nmap → merge
        nmap.go                      # subprocess invocation (-sV --open -T4 -oX -), timeout+kill
        parse.go                     # nmap XML parser (encoding/xml)
        merge.go                     # within-domain replace, cross-domain preserve (§7)
        types.go                     # Target, PortResult, HostGroup
      registry.go                    # name -> Module, and the tool-requirements table the
                                      # setup script and /health both read (single source of truth)
    toolcheck/
      toolcheck.go                   # exec.LookPath / version-check helpers
    logging/
      logging.go                     # log/slog setup, one logger threaded via context
  scripts/
    setup.sh                          # see §9
  docs/
    API.md                            # see §6
    superpowers/specs/                # this file
  config.example.yaml
  README.md
  go.mod / go.sum
  Makefile                            # build, test, run, lint targets
```

## 5. Modules

### 5.1 Subdomain enumeration

Behavior preserved from today: subfinder is the primary tool (`-d <domain> -silent`);
if its binary isn't configured or isn't found, fall back to amass (`enum -d <domain>
-timeout <N> -nocolor -oA <prefix>`, JSON output preferred, `.txt` as a secondary
fallback if the JSON file is empty).

Changes:

- **Streaming parse**, not buffer-then-split: subfinder's stdout and amass's JSON-lines
  output are read and parsed line-by-line as they arrive, not accumulated into one
  string and split at the end. Matters for very large domains (subfinder can return
  tens of thousands of names).
- **Discovery dedup** via `map[string]struct{}` — O(1) average insert, O(n) total,
  versus the risk of an accidentally-quadratic dedup if this were done by other means.
- **DNS resolution** becomes a real bounded worker pool: N goroutines (config
  `resolver_workers`, default 50) pull hostnames off a channel, each resolves via
  `net.Resolver` with its own timeout, results go on a result channel collected by the
  caller, `sync.WaitGroup` signals completion. This replaces today's fixed
  batches-of-20 (`Promise.all` per batch, which waits for the slowest name in each
  batch before starting the next) — wall-clock drops from effectively `O(n/20)`
  batches with head-of-line blocking to `O(n/workers)` with none.
- **Merge** ports the exact algorithm built and tested for the Node fix earlier this
  project (see `subdomainReconcile.service.js` / the `scan-helper` Node fix,
  `mergeSubdomainResults`): keyed by exact hostname (not `www.`-stripped — that
  normalization is for root-domain *attribution* only), found-again entries get fresh
  `ip`/`status`/SSL fields but keep every admin-owned field (criticality, owner,
  `source`, `addedAt`, `addedBy`, `lastCheckedAt`, `checkError`); entries the scan
  didn't find this run are retained untouched; new entries are created with
  `source: "scan"`. O(n+m) via a hash map keyed by hostname, not O(n·m).

### 5.2 Port / service scanning

Behavior preserved: target set is the root domain plus its known subdomains scoped to
that domain (same `belongsToDomain` rule: exact match or a `.`-suffixed match against
the normalized root); `nmap` flags stay `-sV --open -T4` (service detection, open ports
only, fast timing, default top-1000 ports — no explicit `-p`, matching today).

Changes:

- **Concurrency**: a real semaphore-bounded worker pool (config `worker_pool`, default
  5) instead of fixed `Promise.all` batches of 3. Same intent (don't run unbounded
  concurrent `nmap` processes), no batch-stall on the slowest host in a batch.
- **Output format**: `-oX -` (XML to stdout) parsed with `encoding/xml`, replacing
  `-oN <tmpfile>` (human-readable text) plus a hand-written line regex. `nmap`'s XML is
  its actual structured, versioned output; parsing it is materially more robust than
  scraping the text report, and drops the temp-file lifecycle entirely (parse straight
  from the subprocess's stdout pipe).
- **Progress**: the in-memory `Job`'s `count` field is updated as each host's scan
  completes (not per fixed-size batch), so a poller sees continuous progress instead of
  jumps of 5.
- **Merge**: confirmed correct as-is, not a bug — every target in scope is actively
  re-scanned every run, so a host with zero open ports this run should show zero open
  ports, not a stale result from an earlier scan. Ported unchanged: other root domains'
  host-groups are preserved; this domain's host-groups are fully replaced by this run's
  findings.

## 6. HTTP API

All endpoints under `/api/v1`. Every endpoint except `/health` requires header
`X-API-Key: <configured value>`; a missing or wrong key returns `401`.

```
POST /api/v1/scans/subdomains
  body: { "domain": "acme.test", "tenantId": "<hex>", "jobId": "<optional, else generated>" }
  -> 202 { "jobId": "..." }

POST /api/v1/scans/ports
  body: { "domain": "acme.test", "tenantId": "<hex>", "jobId": "<optional>" }
  -> 202 { "jobId": "..." }

GET /api/v1/jobs/{id}
  -> 200 {
       "jobId": "...", "module": "subdomains"|"ports", "status": "queued"|"running"|"complete"|"failed",
       "count": 0, "error": "" ,
       "result": [ ... ]   // present only when mode=api_response AND status=complete
     }

GET /api/v1/jobs?tenantId=...&module=...     // optional listing, mirrors today's admin polling use
GET /api/v1/health
  -> 200 { "status": "ok", "mode": "mongo"|"api_response",
           "tools": { "nmap": true, "subfinder": true, "amass": true } }
```

`result`'s shape mirrors the existing `subdomains[]` / `openPorts[]` array shapes the
ThreatIntel backend already understands (same field names), so a caller in
`api_response` mode can persist it however it likes, and a caller who switches from
`mongo` to `api_response` doesn't need to learn a new data shape.

A request for an already-known `jobId` on the same module+domain returns the existing
job (idempotent trigger — mirrors today's `findOneAndUpdate(..., {upsert:true})`
semantics for `ScanJob`).

## 7. Storage & the mode toggle

`storage.Sink` is called once, when a job finishes:

```go
type Sink interface {
    Save(ctx context.Context, job jobs.Job) error
}
```

- **`mode: mongo`** → `mongo_store.go`. Writes to the SAME collections and field shapes
  the ThreatIntel backend already reads: `ScanJob` (`jobId, tenantId, domain, type,
  status, count, error, startedAt, completedAt`) and `CTEMData` (`tenantId,
  subdomains[]`, `openPorts[]`), using the merge algorithms in §5. **This is the
  compatibility contract**: the backend's polling, its snapshot/reconcile logic, and
  its field expectations do not change at all. This is today's only behavior, unchanged
  in outcome, just re-implemented.
- **`mode: api_response`** → `noop_store.go`. Does nothing; the completed `Job` (with
  its typed `Result`) already lives in the in-memory `JobStore`, which
  `handlers_jobs.go` serves directly. No database is required to run in this mode.

The in-memory `JobStore` (§4, `internal/jobs`) exists **regardless of mode** — it is
what makes `GET /jobs/{id}` and progressive `count` updates work the same way whether
or not Mongo is configured. `mode` only decides whether the storage layer *additionally*
persists to Mongo.

## 8. Configuration

`config.yaml` (path via `-config` flag or `SCAN_HELPER_CONFIG` env var, default
`./config.yaml`):

```yaml
server:
  port: 4001
  api_key: "changeme"              # required on every request except /health

mode: mongo                        # "mongo" | "api_response"

mongo:                             # read only when mode: mongo; ignored otherwise
  uri: "mongodb://localhost:27017/ThreatIntel"

modules:
  subdomain:
    enabled: true
    subfinder_bin: "/root/go/bin/subfinder"
    amass_bin: "/usr/lib/amass/amass"
    timeout_minutes: 5
    resolver_workers: 50
  portscan:
    enabled: true
    nmap_bin: "/usr/bin/nmap"
    timeout_minutes: 10
    worker_pool: 5
```

Every field has a default matching today's `.env` defaults (`internal/config`); the
file only needs to override what differs. `api_key` has NO default — the server refuses
to start without one set, so a fresh deployment can't accidentally run open.

README documents, explicitly:
- how to switch `mode` between `mongo` and `api_response` and what changes in the API
  response when you do (§6);
- exactly where to put MongoDB credentials (the `mongo.uri` field above), and that
  it's ignored/optional when `mode: api_response`;
- that `modules.*.enabled: false` fully disables a module — it won't be routed, and the
  setup script won't require its tools.

## 9. Setup script (`scripts/setup.sh`)

1. **Detect distro** via `/etc/os-release`. Kali → module tools (`nmap`, `subfinder`,
   `amass`) are expected to already be present, script only verifies. Non-Kali
   (Ubuntu, etc.) → offers to install them.
2. **Base prerequisite: the Go toolchain itself.** Needed to build the binary on
   *every* platform, Kali included (Kali does not ship Go by default any more than
   Ubuntu does) — checked and, if missing, installed the same way regardless of
   distro, before any module-specific step. A pinned Go version is recorded in the
   script so "go build works" isn't left to whatever happens to be on the box.
3. **Module selection**: an interactive checklist (default: all modules selected).
4. **Compute required tools** from the *same* `modules/registry.go` metadata the binary
   itself uses (`RequiredTools()` on each selected module) — one table, read by both
   the script (as a small generated/embedded manifest) and the binary's own
   `/health` check, so they cannot drift apart.
5. **Check each required tool** (`command -v`); print a clear present/missing table.
6. On non-Kali with missing tools: install via `apt` where packaged (`nmap`); for
   `subfinder`/`amass` (not in Ubuntu's default repos), download the pinned-version
   release binary for the host architecture — versions pinned alongside the Go version
   from step 2, not "whatever's latest today." Re-verify after install; **hard-fail
   with a clear message** (per your original ask) if something still can't be resolved
   automatically — never silently continue with a module half-configured.
7. **Prompt for mode** (`mongo` / `api_response`); if `mongo`, prompt for the URI and
   write it into `config.yaml`; generate an `api_key` if the user doesn't supply one.
8. **Build** (`go build -o scan-helper ./cmd/scan-helper`) and print the run command.

Re-running `setup.sh` is safe: it re-checks tools and only rewrites `config.yaml` on
explicit confirmation (never clobbers an existing configured deployment silently).

## 10. Error handling

- A module's `Run` returns a typed error; the job transitions to `failed` with that
  message recorded (mirrors today's `ScanJob.status = 'failed', error: err.message`).
- Subprocess timeouts (`context.WithTimeout` wrapping the exec) kill the process
  (`SIGTERM`, matching today) and surface as a normal `failed` job — not a server
  crash.
- `mongo_store.Save` failing (e.g., Mongo unreachable in `mongo` mode) is logged and
  surfaces on the job as an error status; it does not panic the server.
- A panic anywhere in a handler is recovered by middleware and returns `500` — the
  server keeps running other jobs.

## 11. Testing / QA

- **Unit tests per package**: `parse_test.go` for both modules pinned against real
  recorded fixture output (an actual `nmap -oX` sample, an actual `subfinder`/`amass`
  output sample) — not synthetic data; `merge_test.go` for both modules' merge
  semantics (found/not-found/new for subdomains; within-domain-replace/
  cross-domain-preserve for ports); `resolve_test.go` for the worker pool (correct
  results, respects cancellation, bounded concurrency).
- **Config tests**: defaults, validation (missing `api_key` refuses to start, missing
  `mongo.uri` under `mode: mongo` refuses to start).
- **API tests**: `httptest` against the router — auth enforcement, job lifecycle,
  both response modes (assert `result` is present/absent as expected).
- **Integration QA on WSL Ubuntu** (explicit go-ahead given): install `nmap` +
  `subfinder` there, run `scripts/setup.sh` end-to-end (both the "tools present" and
  "tools missing → auto-install" paths, by temporarily hiding a binary from `PATH` for
  the second), start the binary in both modes, and:
  - `mode: mongo` — run a real subdomain scan against a domain you own, verify
    `CTEMData.subdomains` is upserted correctly, including that a hand-inserted "manual"
    entry survives a rescan (the exact regression this session already fixed once on
    the Node side — must not reappear here);
  - `mode: api_response` — run the same scan, verify `GET /jobs/{id}` returns the full
    result inline once complete, with no Mongo involved at all;
  - a real (bounded, `--top-ports` default, single safe target such as
    `scanme.nmap.org` or a host you own) port scan in both modes.

## 12. Documentation

- `README.md`: what this is, quick start (clone → `setup.sh` → run), the mode toggle
  and where Mongo credentials go (§8), module enable/disable, troubleshooting
  (tool-not-found messages, common `nmap` permission notes for unprivileged scans).
- `docs/API.md`: full endpoint reference (§6) with example requests/responses for both
  modes.
