# scan-helper API

Base path: `/api/v1`. All bodies are JSON.

## Authentication

Every endpoint except `GET /api/v1/health` requires the API key from
`config.yaml`:

```
X-API-Key: <server.api_key>
```

A missing or wrong key returns `401`:

```json
{ "error": "invalid or missing X-API-Key" }
```

## How a scan works

Scans take minutes, so they never block an HTTP request:

1. `POST /api/v1/scans/{module}` accepts the work and returns a job id.
2. `GET /api/v1/jobs/{id}` reports progress.
3. When `status` is `complete`, the result is either in your MongoDB
   (`mode: mongo`) or in the `result` field of that same response
   (`mode: api_response`).

---

## `GET /api/v1/health`

No authentication. Reports the active mode, the enabled modules, and
whether each required tool was found on the machine.

```json
{
  "status": "ok",
  "mode": "mongo",
  "modules": ["subdomains", "ports"],
  "tools": { "amass": true, "subfinder": true, "nmap": true }
}
```

`tools` is deduplicated by tool name across modules (e.g. if two modules
both needed the same binary, it would still appear once).

---

## `POST /api/v1/scans/subdomains`

Enumerates subdomains of `domain` and resolves each to an IP.

**Request**

```json
{
  "domain": "example.com",
  "tenantId": "6a7dc0f5458d051280d196ad",
  "jobId": "optional-your-own-id"
}
```

| Field | Required | Notes |
|---|---|---|
| `domain` | yes | The root domain to enumerate |
| `tenantId` | yes | In `mongo` mode this must be a MongoDB ObjectId — it's the `CTEMData.tenantId` results are written under |
| `jobId` | no | Supply your own to correlate with your records; otherwise one is generated (`{module}-{unixnano}`). Re-posting a known `jobId` returns the existing job instead of starting a second scan. |

**Response — `202 Accepted`**

```json
{ "jobId": "subdomains-1695000000000000000" }
```

**Errors:** `400` missing `domain`/`tenantId` or a non-JSON body;
`404` the module is disabled or misspelled; `401` bad key.

---

## `POST /api/v1/scans/ports`

Scans the domain and its known subdomains for open ports and services
(`nmap -sV --open -T4 -oX -`, default top-1000 ports).

Request and responses are identical to the subdomain endpoint.

Which hosts get scanned depends on the mode:

- **`mongo`** — the root domain plus every stored subdomain of it
  (`CTEMData.subdomains`). Subdomains of a *different* root domain are
  never touched.
- **`api_response`** — nothing is stored, so just the domain itself.

---

## `GET /api/v1/jobs/{id}`

```json
{
  "jobId": "subdomains-1695000000000000000",
  "module": "subdomains",
  "tenantId": "6a7dc0f5458d051280d196ad",
  "domain": "example.com",
  "status": "complete",
  "count": 42,
  "startedAt": "2026-09-22T10:00:00Z",
  "completedAt": "2026-09-22T10:01:30Z",
  "result": { "...": "only in api_response mode" }
}
```

| Field | Notes |
|---|---|
| `status` | `running`, `complete` or `failed` |
| `count` | Findings so far — subdomains found, or open ports found. Updates while the scan runs. |
| `error` | Present only when `status` is `failed` |
| `result` | Present only when `mode` is `api_response` **and** `status` is `complete`. In `mongo` mode it is always omitted, whatever the status: the data is already in your database. |

`404` if the job id is unknown.

### `result` — subdomains

```json
{
  "domain": "example.com",
  "subdomains": [
    { "sub": "www.example.com", "ip": "93.184.216.34", "status": "Active" },
    { "sub": "vpn.example.com", "ip": "", "status": "Inactive" }
  ]
}
```

This is the raw finding for this run — the module's own output, before
any merge with previously stored state. Admin-owned fields
(`assetCriticality`, `ownerEmail`, `source`, etc.) only ever appear on
stored `CTEMData.subdomains` entries in `mongo` mode; a fresh scan result
doesn't set them, so they're omitted here.

### `result` — ports

```json
{
  "domain": "example.com",
  "hostGroups": [
    {
      "host": "www.example.com",
      "ip": "93.184.216.34",
      "rootDomain": "example.com",
      "ports": [
        { "port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.18.0", "state": "Open", "risk": "Low" }
      ]
    }
  ]
}
```

A host with no open ports is omitted rather than returned empty.

---

## `GET /api/v1/jobs`

Every job this process knows about, newest state included. Optional
filters: `?tenantId=...`, `?module=subdomains|ports`.

Jobs live in memory, so this list resets when the service restarts. In
`mongo` mode the durable record is the `ScanJob` collection.

---

## What `mongo` mode writes

**`ScanJob`** — one document per scan, upserted by `jobId`:

| Field | Value |
|---|---|
| `jobId` | The job id |
| `tenantId` | ObjectId from the request |
| `domain` | The scanned domain |
| `type` | `subdomains` (for the `subdomains` module) or `openPorts` (for the `ports` module) |
| `status` | `running`, `complete`, `failed` |
| `count` | Findings |
| `error` | Failure message, when failed |
| `startedAt` / `completedAt` | Timestamps (`completedAt` set once the job reaches a terminal status) |

**`CTEMData`** — one document per tenant, keyed by `tenantId`; this tool
only ever `$set`s the one key it owns per scan:

- `subdomains[]` — upserted. A rescan refreshes what it finds again,
  creates what's new, and **retains** entries it didn't return (a
  hand-added or client-requested subdomain survives a rescan), keeping
  admin-owned fields such as `assetCriticality` and `ownerEmail` on any
  entry it does refresh. Entries belonging to a different root domain
  than the one just scanned are always left untouched.
- `openPorts[]` — the scanned domain's host groups are **replaced** by
  the current run's findings, not merged: every target in scope is
  actively re-scanned each run, so a host with nothing open now really
  has nothing open, and there is no hand-added data to preserve the way
  there is for subdomains. Host groups belonging to other root domains
  are left alone.

If writing the result fails, the job is recorded as `failed` (with the
write error as its `error`) rather than left showing `running` or a
false `complete` — the caller should never see success for data that
was never written.
