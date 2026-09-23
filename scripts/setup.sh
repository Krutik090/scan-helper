#!/usr/bin/env bash
# scan-helper setup: check prerequisites, install what's missing, write a
# config, build the binary.
#
# Kali ships most of the scanning tools already; on other distributions
# this installs them. The Go toolchain is checked on EVERY distribution —
# neither Kali nor Ubuntu ships it by default, and the binary is built
# from source here.
set -euo pipefail

GO_VERSION="1.22.5"
SUBFINDER_VERSION="2.6.6"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

info()  { printf '\033[0;36m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[0;32m  \xe2\x9c\x94\033[0m %s\n' "$*"; }
warn()  { printf '\033[0;33m  !\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31m  \xe2\x9c\x97\033[0m %s\n' "$*" >&2; }
die()   { fail "$*"; exit 1; }

# ── 1. Distribution ──────────────────────────────────────────────────────────
DISTRO="unknown"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO="${ID:-unknown}"
fi
info "Distribution: ${DISTRO}"
if [[ "$DISTRO" == "kali" ]]; then
  ok "Kali — the scanning tools are expected to be present already"
else
  warn "Not Kali — missing scanning tools will be installed with apt"
fi

if ! command -v apt-get >/dev/null 2>&1; then
  die "This script supports apt-based distributions. Install nmap, amass and subfinder by hand, then re-run with SKIP_INSTALL=1."
fi

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || die "Run as root, or install sudo."
  SUDO="sudo"
fi

# ── 2. Go toolchain (needed on every distribution) ───────────────────────────
install_go() {
  local arch tarball
  case "$(uname -m)" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *) die "Unsupported architecture $(uname -m) — install Go ${GO_VERSION} manually." ;;
  esac
  tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
  info "Installing Go ${GO_VERSION}"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"
  export PATH="/usr/local/go/bin:$PATH"
  grep -qs '/usr/local/go/bin' "$HOME/.profile" || echo 'export PATH=/usr/local/go/bin:$PATH' >> "$HOME/.profile"
}

info "Checking the Go toolchain"
if command -v go >/dev/null 2>&1; then
  ok "go $(go version | awk '{print $3}') found"
else
  install_go
  command -v go >/dev/null 2>&1 || die "Go still not on PATH after install."
  ok "go $(go version | awk '{print $3}') installed"
fi

# ── 3. Module selection ──────────────────────────────────────────────────────
ENABLE_SUBDOMAIN=true
ENABLE_PORTSCAN=true

if [[ "${ASSUME_YES:-0}" != "1" ]]; then
  info "Which modules should this installation run? (default: all)"
  read -rp "  Enable subdomain enumeration? [Y/n] " answer
  [[ "${answer,,}" == "n" ]] && ENABLE_SUBDOMAIN=false
  read -rp "  Enable port and service scanning? [Y/n] " answer
  [[ "${answer,,}" == "n" ]] && ENABLE_PORTSCAN=false
fi

if [[ "$ENABLE_SUBDOMAIN" == "false" && "$ENABLE_PORTSCAN" == "false" ]]; then
  die "At least one module must be enabled."
fi
ok "subdomain=${ENABLE_SUBDOMAIN} portscan=${ENABLE_PORTSCAN}"

# ── 4. Build the binary early ────────────────────────────────────────────────
# Built now (rather than as the last step) so -print-tools below can read
# the required-tool list straight from the binary instead of a hardcoded
# array that could drift from what the modules actually declare.
info "Building"
go build -o scan-helper ./cmd/scan-helper
ok "Built ./scan-helper"

# ── 5. Required tools, derived from the binary itself ────────────────────────
# The single source of truth for "what does this module need" is the
# binary: `./scan-helper -print-tools` walks every module's
# RequiredTools() and prints one "module:tool" line per requirement, using
# config.Defaults() so it works with no config.yaml present. That keeps
# this installer and the binary from ever drifting apart on what's
# required. We only fall back to a hardcoded list if the binary could not
# be built or run above — which should not happen given step 4 just
# succeeded, but a build that produced a binary which fails to execute
# (wrong architecture, corrupted output, etc.) is still possible.
# Hardcoded fallback, used ONLY if the binary just built above cannot be
# executed (e.g. it was built for the wrong architecture). This must stay
# in sync with modules/subdomain and modules/portscan by hand; the
# `-print-tools` path above is what keeps this script from needing to in
# the normal case.
FALLBACK_MANIFEST="subdomains:amass
subdomains:subfinder
ports:nmap"

TOOLS_MANIFEST=""
# The [[ -n ]] check matters: -print-tools could in principle exit 0 with
# empty output (e.g. a registry with no modules), and without it the
# fallback would never trigger — REQUIRED_TOOLS would silently end up
# empty and the script would proceed having verified nothing.
if [[ -x ./scan-helper ]] && TOOLS_MANIFEST="$(./scan-helper -print-tools 2>/dev/null)" && [[ -n "$TOOLS_MANIFEST" ]]; then
  ok "Read the required-tool list from ./scan-helper -print-tools"
else
  warn "Could not read the tool list from the binary — using the hardcoded fallback list"
  TOOLS_MANIFEST="$FALLBACK_MANIFEST"
fi

REQUIRED_TOOLS=()
if [[ "$ENABLE_SUBDOMAIN" == "true" ]]; then
  while IFS= read -r tool; do
    [[ -n "$tool" ]] && REQUIRED_TOOLS+=("$tool")
  done < <(printf '%s\n' "$TOOLS_MANIFEST" | awk -F: '$1=="subdomains"{print $2}')
fi
if [[ "$ENABLE_PORTSCAN" == "true" ]]; then
  while IFS= read -r tool; do
    [[ -n "$tool" ]] && REQUIRED_TOOLS+=("$tool")
  done < <(printf '%s\n' "$TOOLS_MANIFEST" | awk -F: '$1=="ports"{print $2}')
fi

install_subfinder() {
  local arch tarball checksums expected actual
  case "$(uname -m)" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *) die "Unsupported architecture for subfinder: $(uname -m)" ;;
  esac
  tarball="subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip"
  checksums="subfinder_${SUBFINDER_VERSION}_checksums.txt"
  info "Installing subfinder ${SUBFINDER_VERSION}"
  curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/${tarball}" -o "/tmp/${tarball}"

  # A security tool fetched over the network and dropped into
  # /usr/local/bin must be verified before it's installed — an HTTP 200
  # and a successful unzip are not proof the bytes are what
  # projectdiscovery actually published. Verify against the checksums
  # file published alongside the same release; refuse to install, with
  # no fallback to installing unverified, if either step fails.
  if ! curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/${checksums}" -o "/tmp/${checksums}"; then
    rm -f "/tmp/${tarball}"
    die "Could not download ${checksums} to verify the subfinder download — refusing to install an unverified binary."
  fi

  expected="$(awk -v f="$tarball" '$2==f{print $1}' "/tmp/${checksums}")"
  if [[ -z "$expected" ]]; then
    rm -f "/tmp/${tarball}" "/tmp/${checksums}"
    die "No checksum entry for ${tarball} in ${checksums} — refusing to install an unverified binary."
  fi

  actual="$(sha256sum "/tmp/${tarball}" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    rm -f "/tmp/${tarball}" "/tmp/${checksums}"
    die "subfinder checksum mismatch: expected ${expected}, got ${actual} — refusing to install."
  fi
  ok "subfinder checksum verified (sha256 ${actual})"

  $SUDO apt-get install -y unzip >/dev/null
  unzip -oq "/tmp/${tarball}" -d /tmp/subfinder-install
  $SUDO install -m 0755 /tmp/subfinder-install/subfinder /usr/local/bin/subfinder
  rm -rf "/tmp/${tarball}" "/tmp/${checksums}" /tmp/subfinder-install
}

install_tool() {
  case "$1" in
    nmap)      $SUDO apt-get install -y nmap ;;
    amass)     $SUDO apt-get install -y amass ;;
    subfinder) install_subfinder ;;
    *) die "No installation recipe for $1" ;;
  esac
}

info "Checking required tools"
MISSING=()
for tool in "${REQUIRED_TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool — $(command -v "$tool")"
  else
    fail "$tool — not found"
    MISSING+=("$tool")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  if [[ "${SKIP_INSTALL:-0}" == "1" ]]; then
    die "Missing: ${MISSING[*]} (SKIP_INSTALL=1, so nothing was installed)"
  fi
  info "Installing: ${MISSING[*]}"
  $SUDO apt-get update -qq
  for tool in "${MISSING[@]}"; do
    install_tool "$tool"
  done

  info "Re-checking"
  STILL_MISSING=()
  for tool in "${MISSING[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
      ok "$tool — $(command -v "$tool")"
    else
      fail "$tool — still missing"
      STILL_MISSING+=("$tool")
    fi
  done
  # Never continue half-configured: a module whose tool is absent would
  # only fail later, at scan time, on someone else's schedule.
  [[ ${#STILL_MISSING[@]} -eq 0 ]] || die "Could not install: ${STILL_MISSING[*]}. Install them by hand and re-run."
fi

# ── 6. Configuration ─────────────────────────────────────────────────────────
write_config() {
  local mode="$1" mongo_uri="$2" api_key="$3"
  # Bare command names, resolved on PATH at run time by the service
  # itself — not absolute paths baked in from `command -v` here. An
  # operator can still pin an absolute path by editing config.yaml later;
  # the service accepts either.
  local subfinder_bin="subfinder" amass_bin="amass" nmap_bin="nmap"

  cat > config.yaml <<YAML
# Written by scripts/setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
server:
  port: 4001
  api_key: "${api_key}"

mode: ${mode}

mongo:
  uri: "${mongo_uri}"

modules:
  subdomain:
    enabled: ${ENABLE_SUBDOMAIN}
    subfinder_bin: "${subfinder_bin}"
    amass_bin: "${amass_bin}"
    timeout_minutes: 5
    resolver_workers: 50
  portscan:
    enabled: ${ENABLE_PORTSCAN}
    nmap_bin: "${nmap_bin}"
    timeout_minutes: 10
    worker_pool: 5
YAML
  chmod 600 config.yaml
}

# yaml_value: pull a quoted scalar out of the existing config.yaml by key,
# e.g. `api_key: "..."` or `uri: "..."`. Never fails the script even when
# the key is absent (set -e would otherwise abort on grep's no-match exit
# status) — callers just get an empty string.
yaml_value() {
  grep -m1 -E "^[[:space:]]*${2}:" "$1" 2>/dev/null | sed -E 's/^[^"]*"([^"]*)".*/\1/' || true
}

EXISTING_API_KEY=""
EXISTING_MONGO_URI=""
CONFIG_EXISTED=0
if [[ -f config.yaml ]]; then
  CONFIG_EXISTED=1
  EXISTING_API_KEY="$(yaml_value config.yaml api_key)"
  EXISTING_MONGO_URI="$(yaml_value config.yaml uri)"
fi

if [[ "$CONFIG_EXISTED" -eq 1 && "${ASSUME_YES:-0}" != "1" ]]; then
  read -rp "config.yaml already exists. Overwrite it? [y/N] " answer
  if [[ "${answer,,}" != "y" ]]; then
    # The module selection made earlier in *this* run (possibly
    # different from what's on disk) is being discarded along with
    # everything else — say so, so it's never a silent surprise later.
    info "Keeping the existing config.yaml — it was left untouched and may not reflect the module selections made in this run. Edit ./config.yaml directly if you want changes."
    SKIP_CONFIG=1
  fi
elif [[ "$CONFIG_EXISTED" -eq 1 && "${ASSUME_YES:-0}" == "1" ]]; then
  # ASSUME_YES=1 legitimately means "don't prompt me" — overwriting
  # without asking is fine. Minting a fresh, unannounced API key is not:
  # every existing caller is authenticated with the old one and would
  # start getting silent 401s. So the existing key (and Mongo URI) are
  # carried forward below unless this run's caller explicitly overrode
  # them via API_KEY / MONGO_URI — and either way, this is not silent.
  warn "config.yaml already exists — overwriting it because ASSUME_YES=1 (no prompt)."
  info "The existing API key and Mongo URI are preserved unless API_KEY / MONGO_URI were set for this run."
fi

if [[ "${SKIP_CONFIG:-0}" != "1" ]]; then
  MODE="${MODE:-}"
  if [[ -z "$MODE" ]]; then
    info "How should results be returned?"
    echo "  1) mongo        — written straight into MongoDB (what the ThreatIntel platform expects)"
    echo "  2) api_response — returned by GET /api/v1/jobs/{id}; no database needed"
    read -rp "  Choose [1/2] (default 1): " answer
    case "$answer" in
      2) MODE="api_response" ;;
      *) MODE="mongo" ;;
    esac
  fi

  # An override always wins; otherwise reuse what was already configured
  # rather than silently resetting it back to the default.
  MONGO_URI="${MONGO_URI:-${EXISTING_MONGO_URI:-mongodb://localhost:27017/ThreatIntel}}"
  if [[ "$MODE" == "mongo" && "${ASSUME_YES:-0}" != "1" ]]; then
    read -rp "  MongoDB URI [${MONGO_URI}]: " answer
    [[ -n "$answer" ]] && MONGO_URI="$answer"
  fi

  # Same rule for the API key: an explicit override wins; otherwise reuse
  # the existing key so a re-run never silently invalidates every caller
  # already authenticated with it. Only generate a fresh one when there
  # is genuinely no existing key to preserve.
  API_KEY="${API_KEY:-$EXISTING_API_KEY}"
  if [[ -z "$API_KEY" ]]; then
    if [[ "${ASSUME_YES:-0}" != "1" ]]; then
      read -rp "  API key (blank to generate one): " API_KEY
    fi
    [[ -n "$API_KEY" ]] || API_KEY="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
  fi

  write_config "$MODE" "$MONGO_URI" "$API_KEY"
  ok "Wrote config.yaml (mode: ${MODE})"
  info "API key: ${API_KEY}"
fi

cat <<'DONE'

Setup complete. Start it with:

    ./scan-helper -config ./config.yaml

Then check it:

    curl -s localhost:4001/api/v1/health

To switch between MongoDB storage and API responses later, edit `mode`
in config.yaml and restart. See README.md.
DONE
