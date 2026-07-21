require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const { spawn } = require('child_process');
const { randomUUID } = require('crypto');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const os = require('os');

// ─── logger ───────────────────────────────────────────────────────────────────
function ts() { return new Date().toISOString().replace('T', ' ').slice(0, -5) + 'Z'; }
function log(tag, jobId, ...msg)    { const id = jobId ? ` [${String(jobId).slice(0, 8)}]` : ''; console.log( `[${ts()}] [${tag}]${id}`, ...msg); }
function logErr(tag, jobId, ...msg) { const id = jobId ? ` [${String(jobId).slice(0, 8)}]` : ''; console.error(`[${ts()}] [${tag}]${id}`, ...msg); }

const app = express();
app.use(express.json());

// Log every inbound HTTP request
app.use((req, _res, next) => {
  const { domain, tenantId, jobId } = req.body || {};
  const bodyStr = [domain && `domain=${domain}`, tenantId && `tenant=${String(tenantId).slice(-6)}`, jobId && `job=${String(jobId).slice(0, 8)}`]
    .filter(Boolean).join(' ');
  log('http', null, `${req.method} ${req.path}` + (bodyStr ? ` | ${bodyStr}` : ''));
  next();
});

const PORT          = process.env.PORT || 4001;
const MONGODB_URI   = process.env.MONGODB_URI || 'mongodb://localhost:27017/ThreatIntel';
const AMASS_BIN     = process.env.AMASS_BIN || '/usr/lib/amass/amass';
const SUBFINDER_BIN = process.env.SUBFINDER_BIN || '';
const NMAP_BIN      = process.env.NMAP_BIN || '/usr/bin/nmap';
const SCAN_TIMEOUT  = parseInt(process.env.SCAN_TIMEOUT_MINUTES || '5', 10);
const NMAP_TIMEOUT  = parseInt(process.env.NMAP_TIMEOUT_MINUTES || '10', 10);

// ─── minimal schemas (strict:false preserves other fields on upsert) ─────────
const ScanJob = mongoose.model('ScanJob', new mongoose.Schema({
  jobId:       String,
  tenantId:    mongoose.Schema.Types.ObjectId,
  domain:      String,
  type:        String,
  status:      String,
  count:       Number,
  error:       String,
  startedAt:   Date,
  completedAt: Date,
}, { strict: false, timestamps: true }));

const CTEMData = mongoose.model('CTEMData', new mongoose.Schema({
  tenantId:   mongoose.Schema.Types.ObjectId,
  subdomains: mongoose.Schema.Types.Mixed,
}, { strict: false }));

// ─── helpers ─────────────────────────────────────────────────────────────────
async function resolveIP(hostname) {
  try {
    const addrs = await dns.resolve4(hostname);
    return addrs[0] || '';
  } catch {
    return '';
  }
}

function parseAmassJson(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath, 'utf8');
  const results = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      if (obj.name) results.push(obj);
    } catch { /* skip malformed lines */ }
  }
  return results;
}

function parseAmassTxt(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean);
}

function cleanup(...files) {
  for (const f of files) {
    try { fs.unlinkSync(f); } catch { /* ignore */ }
  }
}

// Normalize a hostname for comparison (lowercase, strip trailing dots / leading www.)
function normHost(h) {
  return String(h || '').trim().toLowerCase().replace(/\.+$/, '').replace(/^www\./, '');
}

// Is `host` the root domain itself, or a subdomain of it?
function belongsToDomain(host, domain) {
  const h = normHost(host);
  const d = normHost(domain);
  return !!d && (h === d || h.endsWith('.' + d));
}

// Parse nmap normal-format text output (-oN) into structured port objects
function parseNmapOutput(output) {
  const results = [];
  let inPortSection = false;
  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (/^PORT\s+STATE\s+SERVICE/.test(line)) { inPortSection = true; continue; }
    if (!inPortSection) continue;
    if (line === '' || line.startsWith('Service') || line.startsWith('Nmap') || line.startsWith('Warning')) {
      inPortSection = false;
      continue;
    }
    // e.g. "80/tcp   open  http    nginx 1.18.0"
    const m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$/);
    if (!m) continue;
    const [, portStr, protocol, service, version] = m;
    results.push({
      port:     parseInt(portStr, 10),
      protocol,
      service,
      version:  (version || '').trim(),
      state:    'Open',
      risk:     'Unknown',
    });
  }
  return results;
}

// ─── tool runners ────────────────────────────────────────────────────────────

// subfinder: fast passive enumeration, outputs one name per line to stdout
async function runSubfinder(domain, jobId) {
  return new Promise((resolve) => {
    const args = ['-d', domain, '-silent'];
    log('scan', jobId, `Executing: ${SUBFINDER_BIN} ${args.join(' ')}`);
    const startTime = Date.now();

    const proc = spawn(SUBFINDER_BIN, args, {
      env: { ...process.env, HOME: os.homedir() },
    });
    let buf = '';
    let stderrBuf = '';
    proc.stdout.on('data', d => { buf += d.toString(); });
    proc.stderr.on('data', d => { stderrBuf += d.toString(); });
    proc.on('close', (code) => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const lines = buf.split('\n').map(l => l.trim()).filter(Boolean);
      log('scan', jobId, `subfinder exited (code=${code}) in ${elapsed}s — ${lines.length} names found`);
      if (stderrBuf.trim()) log('scan', jobId, `subfinder stderr: ${stderrBuf.trim().slice(0, 200)}`);
      resolve(lines);
    });
    proc.on('error', (err) => {
      logErr('scan', jobId, `subfinder spawn error: ${err.message}`);
      resolve([]);
    });
  });
}

// amass: comprehensive, outputs files with -oA flag
async function runAmass(domain, prefix, jobId) {
  return new Promise((resolve) => {
    const args = ['enum', '-d', domain, '-timeout', String(SCAN_TIMEOUT), '-nocolor', '-oA', prefix];
    log('scan', jobId, `Executing: ${AMASS_BIN} ${args.join(' ')}`);
    log('scan', jobId, `amass output prefix: ${prefix} | timeout: ${SCAN_TIMEOUT} min`);
    const startTime = Date.now();

    const proc = spawn(AMASS_BIN, args, {
      env: { ...process.env, HOME: os.homedir() },
    });
    proc.stdout.on('data', d => process.stdout.write(`[${ts()}] [amass] ${d}`));
    proc.stderr.on('data', d => process.stderr.write(`[${ts()}] [amass] ${d}`));
    proc.on('close', (code) => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      log('scan', jobId, `amass exited (code=${code}) in ${elapsed}s`);
      resolve(code);
    });
    proc.on('error', (err) => {
      logErr('scan', jobId, `amass spawn error: ${err.message}`);
      resolve(null);
    });
  });
}

// nmap: active port + service scan, writes to temp file then parses
// scanId must be unique per concurrent call (e.g. `${jobId}_${index}`)
async function runNmap(target, jobId, scanId) {
  return new Promise((resolve) => {
    const id = scanId || jobId;
    const outFile = path.join(os.tmpdir(), `nmap_${id}.txt`);
    // -sV: service/version detection, --open: only open ports, -T4: fast timing, top 1000 ports
    const args = ['-sV', '--open', '-T4', '-oN', outFile, target];
    const timeoutMs = NMAP_TIMEOUT * 60 * 1000;

    log('scan', jobId, `Executing nmap on ${target}`);
    const startTime = Date.now();

    const proc = spawn(NMAP_BIN, args);
    // Suppress per-host nmap output for multi-host scans — logged at summary level
    proc.stderr.on('data', () => {});

    const killTimer = setTimeout(() => {
      logErr('scan', jobId, `nmap timed out on ${target} — killing`);
      proc.kill('SIGTERM');
    }, timeoutMs);

    proc.on('close', (code) => {
      clearTimeout(killTimer);
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      let ports = [];
      if (fs.existsSync(outFile)) {
        const content = fs.readFileSync(outFile, 'utf8');
        cleanup(outFile);
        ports = parseNmapOutput(content);
      }
      log('scan', jobId, `nmap [${target}] done in ${elapsed}s | ${ports.length} port(s) open (exit=${code})`);
      resolve(ports);
    });

    proc.on('error', (err) => {
      clearTimeout(killTimer);
      logErr('scan', jobId, `nmap spawn error on ${target}: ${err.message}`);
      cleanup(outFile);
      resolve([]);
    });
  });
}

// ─── core scanners ─────────────────────────────────────────────────────────────
async function runSubdomainScan(domain, tenantId, jobId) {
  log('scan', jobId, `▶ Starting subdomain scan | domain=${domain} tenantId=${tenantId}`);

  await ScanJob.findOneAndUpdate(
    { jobId },
    { jobId, tenantId, domain, type: 'subdomains', status: 'running', startedAt: new Date() },
    { upsert: true }
  );
  log('scan', jobId, 'ScanJob status → running');

  let names = [];
  const subfinderAvailable = SUBFINDER_BIN && fs.existsSync(SUBFINDER_BIN);

  if (subfinderAvailable) {
    log('scan', jobId, `Tool selected: subfinder (${SUBFINDER_BIN})`);
    names = await runSubfinder(domain, jobId);
    log('scan', jobId, `subfinder produced ${names.length} name(s)`);
  } else {
    if (!SUBFINDER_BIN) {
      log('scan', jobId, 'Tool selected: amass (subfinder not configured in .env)');
    } else {
      log('scan', jobId, `Tool selected: amass (subfinder binary missing at ${SUBFINDER_BIN})`);
    }

    const prefix = path.join(os.tmpdir(), `scan_${jobId}`);
    await runAmass(domain, prefix, jobId);

    const jsonFile = `${prefix}.json`;
    const txtFile  = `${prefix}.txt`;

    const jsonExists = fs.existsSync(jsonFile);
    const txtExists  = fs.existsSync(txtFile);
    log('scan', jobId, `amass output files — json: ${jsonExists} | txt: ${txtExists}`);

    const jsonEntries = parseAmassJson(jsonFile);
    log('scan', jobId, `amass JSON parsed: ${jsonEntries.length} entries`);

    if (jsonEntries.length > 0) {
      const subdomains = jsonEntries.map(e => ({
        sub:              e.name,
        ip:               e.addresses?.[0]?.ip || '',
        status:           'Active',
        assetCriticality: 'Low',
        sslGrade:         'N/A',
        sslDaysRemaining: null,
      }));

      const missing = subdomains.filter(s => !s.ip);
      log('scan', jobId, `Resolving IPs for ${missing.length}/${subdomains.length} entries missing an IP...`);
      for (let i = 0; i < missing.length; i += 20) {
        await Promise.all(missing.slice(i, i + 20).map(async s => { s.ip = await resolveIP(s.sub); }));
      }
      const resolved = subdomains.filter(s => s.ip).length;
      log('scan', jobId, `IP resolution done: ${resolved}/${subdomains.length} resolved`);

      cleanup(jsonFile, txtFile);
      log('scan', jobId, `Temp files cleaned: ${jsonFile}`);
      await saveSubdomainResults(tenantId, jobId, domain, subdomains);
      return;
    }

    names = parseAmassTxt(txtFile);
    cleanup(jsonFile, txtFile);
    log('scan', jobId, `amass JSON was empty — falling back to txt: ${names.length} names`);
  }

  log('scan', jobId, `Resolving IPs for ${names.length} subdomains in batches of 20...`);
  const BATCH = 20;
  const subdomains = new Array(names.length);
  for (let i = 0; i < names.length; i += BATCH) {
    const slice = names.slice(i, i + BATCH);
    const resolved = await Promise.all(slice.map(sub => resolveIP(sub)));
    slice.forEach((sub, j) => {
      subdomains[i + j] = {
        sub,
        ip:               resolved[j],
        status:           'Active',
        assetCriticality: 'Low',
        sslGrade:         'N/A',
        sslDaysRemaining: null,
      };
    });
    if (i % 100 === 0 && i > 0) {
      log('scan', jobId, `IP resolution progress: ${Math.min(i + BATCH, names.length)}/${names.length}`);
    }
  }

  const withIp = subdomains.filter(s => s.ip).length;
  log('scan', jobId, `IP resolution done: ${withIp}/${subdomains.length} resolved`);
  await saveSubdomainResults(tenantId, jobId, domain, subdomains);
}

async function runOpenPortsScan(domain, tenantId, jobId) {
  log('scan', jobId, `▶ Starting open ports scan | rootDomain=${domain} tenantId=${tenantId}`);
  const oid = new mongoose.Types.ObjectId(tenantId);
  const root = normHost(domain);

  await ScanJob.findOneAndUpdate(
    { jobId },
    { jobId, tenantId, domain, type: 'openPorts', status: 'running', startedAt: new Date() },
    { upsert: true }
  );
  log('scan', jobId, 'ScanJob status → running');

  // Scope to THIS root domain: scan the root domain + only ITS subdomains, so
  // port-scanning bbb.com neither scans nor overwrites aaa.com's hosts.
  const ctemDoc = await CTEMData.findOne({ tenantId: oid }).lean();
  const domainSubs = (ctemDoc?.subdomains || []).filter(s => s && s.sub && belongsToDomain(s.sub, domain));

  const seen = new Set([root]);
  const targets = [{ host: domain, ip: '' }];
  for (const s of domainSubs) {
    const h = normHost(s.sub);
    if (!seen.has(h)) { seen.add(h); targets.push({ host: s.sub, ip: s.ip || '' }); }
  }
  log('scan', jobId, `Target list for ${domain}: ${targets.length} host(s) — root + ${targets.length - 1} subdomain(s)`);

  // Scan in concurrent batches of 3
  const CONCURRENCY = 3;
  const results = [];
  let totalPorts = 0;

  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    const batch = targets.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async (target, bi) => {
        const scanId = `${jobId}_${i + bi}`;
        const ports = await runNmap(target.host, jobId, scanId);
        return { ...target, ports };
      })
    );

    for (const result of batchResults) {
      if (result.ports.length > 0) {
        // Stamp the owning root domain so results group per-domain on read.
        results.push({ host: result.host, ip: result.ip, ports: result.ports, rootDomain: root });
        totalPorts += result.ports.length;
      }
    }

    // Progressive count update so frontend polling shows progress
    await ScanJob.findOneAndUpdate({ jobId }, { count: totalPorts });
    const done = Math.min(i + CONCURRENCY, targets.length);
    log('scan', jobId, `Progress: ${done}/${targets.length} hosts | ${totalPorts} open ports so far`);
  }

  // MERGE, don't replace: keep every OTHER root domain's host groups and swap in
  // only this domain's — otherwise scanning one domain wiped the others' ports.
  const existing = Array.isArray(ctemDoc?.openPorts) ? ctemDoc.openPorts : [];
  const kept = existing.filter(hg => hg && hg.host && !belongsToDomain(hg.host, domain));
  const merged = kept.concat(results);
  log('scan', jobId, `Merge for ${domain}: kept ${kept.length} host group(s) from other domains + ${results.length} scanned = ${merged.length} total`);

  log('scan', jobId, `Writing ${merged.length} host groups (${totalPorts} ports for ${domain}) to CTEMData...`);
  try {
    await CTEMData.findOneAndUpdate(
      { tenantId: oid },
      { $set: { openPorts: merged } },
      { upsert: true, new: true }
    );
    log('scan', jobId, 'CTEMData updated ✓');
  } catch (err) {
    logErr('scan', jobId, `CTEMData write failed: ${err.message}`);
    throw err;
  }

  await ScanJob.findOneAndUpdate(
    { jobId },
    { status: 'complete', count: totalPorts, completedAt: new Date() },
    { upsert: true }
  );
  log('scan', jobId, `■ Scan complete for ${domain} — ${results.length} hosts, ${totalPorts} ports (${merged.length} host groups total across all domains)`);
}

async function saveSubdomainResults(tenantId, jobId, domain, subdomains) {
  const oid = new mongoose.Types.ObjectId(tenantId);
  const root = normHost(domain);

  // Stamp the owning root domain so results group per-domain (and so merges are
  // precise). The backend also re-derives this on read, but stamping keeps the
  // stored data correct.
  const scanned = subdomains.map(s => ({ ...s, rootDomain: root }));

  // MERGE, don't replace. A tenant can own several root domains, each scanned
  // separately; `$set: { subdomains }` with only this domain's results wiped the
  // others. Keep every OTHER domain's subdomains intact and swap in only the ones
  // for the domain we just scanned. Preserve admin-managed fields (criticality,
  // SSL/cert-expiry) for subdomains that still exist by name across a re-scan.
  const existingDoc = await CTEMData.findOne({ tenantId: oid }).lean();
  const existing = Array.isArray(existingDoc?.subdomains) ? existingDoc.subdomains : [];

  const prevForDomain = new Map();
  const kept = [];
  for (const s of existing) {
    if (s && belongsToDomain(s.sub, domain)) prevForDomain.set(normHost(s.sub), s);
    else kept.push(s);
  }

  const mergedForDomain = scanned.map(s => {
    const prev = prevForDomain.get(normHost(s.sub));
    if (!prev) return s;
    return {
      ...s,
      assetCriticality: prev.assetCriticality || s.assetCriticality,
      sslGrade:         prev.sslGrade || s.sslGrade,
      sslDaysRemaining: prev.sslDaysRemaining != null ? prev.sslDaysRemaining : s.sslDaysRemaining,
      ...(prev.sslExpiresAt ? { sslExpiresAt: prev.sslExpiresAt } : {}),
    };
  });

  const merged = kept.concat(mergedForDomain);
  log('scan', jobId, `Merge for ${domain}: kept ${kept.length} from other domains + ${mergedForDomain.length} scanned = ${merged.length} total`);

  log('scan', jobId, `Writing ${merged.length} subdomains to CTEMData...`);
  try {
    await CTEMData.findOneAndUpdate(
      { tenantId: oid },
      { $set: { subdomains: merged } },
      { upsert: true, new: true }
    );
    log('scan', jobId, `CTEMData updated ✓`);
  } catch (err) {
    logErr('scan', jobId, `CTEMData write failed: ${err.message}`);
    throw err;
  }

  log('scan', jobId, `Marking ScanJob complete...`);
  try {
    await ScanJob.findOneAndUpdate(
      { jobId },
      { status: 'complete', count: scanned.length, completedAt: new Date() },
      { upsert: true }
    );
    log('scan', jobId, `ScanJob status → complete (count=${scanned.length}) ✓`);
  } catch (err) {
    logErr('scan', jobId, `ScanJob write failed: ${err.message}`);
    throw err;
  }

  log('scan', jobId, `■ Scan complete — ${scanned.length} subdomains for ${domain} saved (${merged.length} total across all domains)`);
}

// ─── routes ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => {
  const subfinderOk = Boolean(SUBFINDER_BIN && fs.existsSync(SUBFINDER_BIN));
  const amassOk     = fs.existsSync(AMASS_BIN);
  const nmapOk      = fs.existsSync(NMAP_BIN);
  res.json({ status: 'ok', amassOk, subfinderOk, nmapOk, nmap: NMAP_BIN });
});

app.post('/scan/subdomains', async (req, res) => {
  const { domain, tenantId, jobId } = req.body;

  if (!domain || !tenantId || !jobId) {
    logErr('helper', jobId || null, `Bad request — missing fields. Got: domain=${domain} tenantId=${tenantId} jobId=${jobId}`);
    return res.status(400).json({ error: 'domain, tenantId, jobId are required' });
  }

  log('helper', jobId, `Accepted subdomain scan request for domain=${domain}`);
  res.json({ accepted: true, jobId });

  runSubdomainScan(domain, tenantId, jobId).catch(async (err) => {
    logErr('scan', jobId, `Unhandled scan error: ${err.message}`);
    if (err.stack) logErr('scan', jobId, err.stack.split('\n').slice(1, 4).join(' | '));
    try {
      await ScanJob.findOneAndUpdate(
        { jobId },
        { status: 'failed', error: err.message, completedAt: new Date() }
      );
      log('scan', jobId, 'ScanJob status → failed (written to DB)');
    } catch (dbErr) {
      logErr('scan', jobId, `Could not write failed status to DB: ${dbErr.message}`);
    }
  });
});

app.post('/scan/openports', async (req, res) => {
  const { domain, tenantId, jobId } = req.body;

  if (!domain || !tenantId || !jobId) {
    logErr('helper', jobId || null, `Bad request — missing fields`);
    return res.status(400).json({ error: 'domain, tenantId, jobId are required' });
  }

  log('helper', jobId, `Accepted open ports scan request for domain=${domain}`);
  res.json({ accepted: true, jobId });

  runOpenPortsScan(domain, tenantId, jobId).catch(async (err) => {
    logErr('scan', jobId, `Unhandled open ports scan error: ${err.message}`);
    if (err.stack) logErr('scan', jobId, err.stack.split('\n').slice(1, 4).join(' | '));
    try {
      await ScanJob.findOneAndUpdate(
        { jobId },
        { status: 'failed', error: err.message, completedAt: new Date() }
      );
      log('scan', jobId, 'ScanJob status → failed (written to DB)');
    } catch (dbErr) {
      logErr('scan', jobId, `Could not write failed status to DB: ${dbErr.message}`);
    }
  });
});

// ─── startup ─────────────────────────────────────────────────────────────────
log('startup', null, `scan-helper initializing | port=${PORT} mongodb=${MONGODB_URI}`);

mongoose.connect(MONGODB_URI)
  .then(() => {
    log('startup', null, `MongoDB connected ✓ | ${MONGODB_URI}`);

    if (!fs.existsSync(AMASS_BIN)) {
      logErr('startup', null, `amass NOT found at ${AMASS_BIN}`);
    } else {
      log('startup', null, `amass found ✓ | ${AMASS_BIN}`);
    }

    if (!SUBFINDER_BIN) {
      log('startup', null, 'subfinder not configured (SUBFINDER_BIN not set) — will fall back to amass');
    } else if (!fs.existsSync(SUBFINDER_BIN)) {
      logErr('startup', null, `subfinder configured but NOT found at ${SUBFINDER_BIN}`);
      log('startup', null, 'Falling back to amass for all scans');
    } else {
      log('startup', null, `subfinder found ✓ | ${SUBFINDER_BIN} (primary tool for subdomain scans)`);
    }

    if (!fs.existsSync(NMAP_BIN)) {
      logErr('startup', null, `nmap NOT found at ${NMAP_BIN}`);
      logErr('startup', null, 'Install: apt install nmap  OR set NMAP_BIN in .env');
    } else {
      log('startup', null, `nmap found ✓ | ${NMAP_BIN} (used for open ports scans)`);
    }

    app.listen(PORT, '0.0.0.0', () => {
      log('startup', null, `✓ scan-helper ready — listening on http://0.0.0.0:${PORT}`);
      log('startup', null, '─────────────────────────────────────────────────────────');
    });
  })
  .catch(err => {
    logErr('startup', null, `MongoDB connection FAILED: ${err.message}`);
    process.exit(1);
  });
