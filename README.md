# scan-helper

A small Go service that runs recon tooling and hands the results back —
either written straight into MongoDB, or returned from its own API.

Two modules today:

| Module | API name | What it does | Tools it needs |
|---|---|---|---|
| Subdomain enumeration | `subdomains` | Enumerates a domain's subdomains, resolves each to an IP | `subfinder` (preferred), `amass` (fallback) |
| Port and service scan | `ports` | Scans the domain and its known subdomains for open ports and services | `nmap` |

## Requirements

**Kali Linux is recommended** — it already ships the scanning tools. On
other apt-based distributions (Ubuntu, Debian) the setup script installs
what's missing. The Go toolchain is installed by the script on any
distribution, since the binary is built from source.

## Install

```bash
git clone https://github.com/Krutik090/scan-helper.git
cd scan-helper
./scripts/setup.sh
```

The script, in order:

1. detects your distribution (apt-based only; Kali is assumed to already
   have the scanning tools),
2. checks for the Go toolchain and installs it if missing,
3. asks which modules you want — all of them by default,
4. builds `./scan-helper`,
5. asks the freshly built binary which tools those modules actually need
   (`./scan-helper -print-tools`, filtered to your module choices) and
   checks each is on `PATH`; anything missing is installed (subfinder's
   download is verified against its published SHA-256 checksum before
   it's installed), and the script stops with a clear error if a
   required tool still can't be found afterwards,
6. asks how results should be returned and writes `config.yaml` (mode
   `600`, since it can hold a database password) — a re-run that finds
   an existing `config.yaml` asks before overwriting it, and preserves
   the existing `api_key` and `mongo.uri` rather than minting new ones.

Then:

```bash
./scan-helper -config ./config.yaml
curl -s localhost:4001/api/v1/health
```

## The two result modes

This is the one setting most people need to think about. It lives at the
top of `config.yaml`:

```yaml
mode: mongo          # or: api_response
```

### `mode: mongo` — results go into your database

Scan results are written directly into MongoDB. The API only tells you
whether the job finished; the data itself is in your database by the
time it does. This is the mode the ThreatIntel platform uses: the
scanner and the platform share one database, so nothing has to be copied
between them.

Put your credentials in the URI:

```yaml
mode: mongo
mongo:
  uri: "mongodb://username:password@localhost:27017/ThreatIntel"
```

The URI **must name a database** (the `/ThreatIntel` at the end). Two
collections are written: `ScanJob` (one document per scan, with status
and counts) and `CTEMData` (one document per tenant, holding
`subdomains` and `openPorts`).

Because the file holds a password, `setup.sh` writes `config.yaml` with
mode `600`. Keep it that way.

### `mode: api_response` — results come back from the API

Nothing is stored. You start a scan, poll its job, and the finished
result is in the response. No database, no credentials, no schema to
agree on.

```yaml
mode: api_response
# the mongo: block is ignored entirely in this mode
```

### Switching between them

1. Edit `mode` in `config.yaml`.
2. If you're switching *to* `mongo`, fill in `mongo.uri`.
3. Restart: `./scan-helper -config ./config.yaml`.
4. Confirm: `curl -s localhost:4001/api/v1/health` reports the active mode.

Switching doesn't migrate anything. Results produced in one mode stay
where that mode put them.

## Using it

Every endpoint except `/api/v1/health` needs your API key:

```bash
KEY=$(grep api_key config.yaml | cut -d'"' -f2)

# start a scan
curl -s -X POST localhost:4001/api/v1/scans/subdomains \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","tenantId":"6a7dc0f5458d051280d196ad"}'
# -> {"jobId":"subdomains-1695..."}

# poll it
curl -s localhost:4001/api/v1/jobs/subdomains-1695... -H "X-API-Key: $KEY"
```

Full endpoint reference: [docs/API.md](docs/API.md).

## Turning a module off

```yaml
modules:
  portscan:
    enabled: false
```

A disabled module isn't routed (its endpoint returns 404) and its tools
aren't required. At least one module must stay enabled — the server
refuses to start otherwise.

## Configuration reference

| Key | Default | Meaning |
|---|---|---|
| `server.port` | `4001` | Listen port |
| `server.api_key` | *(none — required)* | Value callers must send as `X-API-Key`. The server refuses to start without it. |
| `mode` | `mongo` | `mongo` or `api_response` |
| `mongo.uri` | `mongodb://localhost:27017/ThreatIntel` | Connection string, including the database name. Only read in `mongo` mode; the server refuses to start with `mode: mongo` and an empty URI. |
| `modules.subdomain.enabled` | `true` | |
| `modules.subdomain.subfinder_bin` | `subfinder` | A bare command name is resolved on `PATH` at run time; give an absolute path instead to pin a specific binary. Leave it empty (`subfinder_bin: ""`) to always use amass. |
| `modules.subdomain.amass_bin` | `amass` | Same rule: bare name resolves on `PATH`, or give an absolute path |
| `modules.subdomain.timeout_minutes` | `5` | Per-scan timeout |
| `modules.subdomain.resolver_workers` | `50` | Concurrent DNS lookups |
| `modules.portscan.enabled` | `true` | |
| `modules.portscan.nmap_bin` | `nmap` | Same rule: bare name resolves on `PATH`, or give an absolute path |
| `modules.portscan.timeout_minutes` | `10` | Per-host nmap timeout |
| `modules.portscan.worker_pool` | `5` | Hosts scanned concurrently |

## Troubleshooting

**`required tool not found — scans needing it will fail` in the logs at
start-up.** This is a warning, not a start-up failure: the server still
starts, but a scan that needs the missing tool will fail when it runs.
Check with `command -v nmap` (or `subfinder`, `amass`) and either put it
on `PATH` or point the relevant `*_bin` key at its absolute path. You can
also ask the binary itself what it needs: `./scan-helper -print-tools`.

**Port scans find nothing.** Unprivileged nmap can't use SYN scanning.
Either run scan-helper as root, or grant the capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
```

**`mongo.uri must name a database`.** Add the database to the end of the
URI: `mongodb://localhost:27017/ThreatIntel`.

**401 on every request.** The `X-API-Key` header doesn't match
`server.api_key` in `config.yaml`.

## Development

```bash
make test      # go test ./... -count=1
make test-race # the same under the race detector (needs cgo and a C toolchain)
make build     # go build -o scan-helper ./cmd/scan-helper
make run       # build, then ./scan-helper -config ./config.yaml
```

`make test` runs everywhere. `make test-race` needs a C compiler, since
the race detector is built on cgo — it is the right target for CI, and it
will not run on a box without one.

The storage tests skip unless `SCAN_HELPER_TEST_MONGO_URI` points at a
throwaway database; they delete the collections they use, so never point
them at a real one:

```bash
SCAN_HELPER_TEST_MONGO_URI=mongodb://localhost:27017/scanhelper_test \
  go test ./internal/storage/ -count=1
```

`./scan-helper -print-tools` prints one `module:tool` line per tool every
registered module needs (it works with no `config.yaml` present, since it
reads the built-in defaults) — useful for confirming what a given build
actually requires:

```
$ ./scan-helper -print-tools
subdomains:amass
subdomains:subfinder
ports:nmap
```
