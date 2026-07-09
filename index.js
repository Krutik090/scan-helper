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

const PORT        = process.env.PORT || 4001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ThreatIntel';
const AMASS_BIN   = process.env.AMASS_BIN || '/usr/lib/amass/amass';
const SUBFINDER_BIN = process.env.SUBFINDER_BIN || '';
const SCAN_TIMEOUT  = parseInt(process.env.SCAN_TIMEOUT_MINUTES || '5', 10);

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

// ─── core scanner ─────────────────────────────────────────────────────────────
async function runSubdomainScan(domain, tenantId, jobId) {
  log('scan', jobId, `▶ Starting subdomain scan | domain=${domain} tenantId=${tenantId}`);

  // Mark running (upsert: true so direct-to-helper tests also work)
  await ScanJob.findOneAndUpdate(
    { jobId },
    { jobId, tenantId, domain, type: 'subdomains', status: 'running', startedAt: new Date() },
    { upsert: true }
  );
  log('scan', jobId, 'ScanJob status → running');

  let names = [];
  const subfinderAvailable = SUBFINDER_BIN && fs.existsSync(SUBFINDER_BIN);

  if (subfinderAvailable) {
    // ── Fast path: subfinder ───────────────────────────────────────────
    log('scan', jobId, `Tool selected: subfinder (${SUBFINDER_BIN})`);
    names = await runSubfinder(domain, jobId);
    log('scan', jobId, `subfinder produced ${names.length} name(s)`);
  } else {
    // ── Fallback: amass ────────────────────────────────────────────────
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
      await saveResults(tenantId, jobId, subdomains);
      return;
    }

    // txt fallback
    names = parseAmassTxt(txtFile);
    cleanup(jsonFile, txtFile);
    log('scan', jobId, `amass JSON was empty — falling back to txt: ${names.length} names`);
  }

  // Resolve IPs for name-only lists (subfinder / amass txt)
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
  await saveResults(tenantId, jobId, subdomains);
}

async function saveResults(tenantId, jobId, subdomains) {
  log('scan', jobId, `Writing ${subdomains.length} subdomains to CTEMData...`);
  try {
    await CTEMData.findOneAndUpdate(
      { tenantId: new mongoose.Types.ObjectId(tenantId) },
      { $set: { subdomains } },
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
      { status: 'complete', count: subdomains.length, completedAt: new Date() },
      { upsert: true }
    );
    log('scan', jobId, `ScanJob status → complete (count=${subdomains.length}) ✓`);
  } catch (err) {
    logErr('scan', jobId, `ScanJob write failed: ${err.message}`);
    throw err;
  }

  log('scan', jobId, `■ Scan complete — ${subdomains.length} subdomains saved to DB`);
}

// ─── routes ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => {
  const subfinderOk = Boolean(SUBFINDER_BIN && fs.existsSync(SUBFINDER_BIN));
  const amassOk     = fs.existsSync(AMASS_BIN);
  res.json({ status: 'ok', amass: AMASS_BIN, amassOk, subfinder: SUBFINDER_BIN || null, subfinderOk });
});

app.post('/scan/subdomains', async (req, res) => {
  const { domain, tenantId, jobId } = req.body;

  if (!domain || !tenantId || !jobId) {
    logErr('helper', jobId || null, `Bad request — missing fields. Got: domain=${domain} tenantId=${tenantId} jobId=${jobId}`);
    return res.status(400).json({ error: 'domain, tenantId, jobId are required' });
  }

  log('helper', jobId, `Accepted scan request for domain=${domain}`);

  // Respond immediately — scan runs in background
  res.json({ accepted: true, jobId });

  // Run scan async (errors are caught and written to ScanJob)
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

// ─── startup ─────────────────────────────────────────────────────────────────
log('startup', null, `scan-helper initializing | port=${PORT} mongodb=${MONGODB_URI}`);

mongoose.connect(MONGODB_URI)
  .then(() => {
    log('startup', null, `MongoDB connected ✓ | ${MONGODB_URI}`);

    // Check amass
    if (!fs.existsSync(AMASS_BIN)) {
      logErr('startup', null, `amass NOT found at ${AMASS_BIN}`);
      logErr('startup', null, 'Install: apt install amass  OR set AMASS_BIN in .env');
    } else {
      log('startup', null, `amass found ✓ | ${AMASS_BIN}`);
    }

    // Check subfinder
    if (!SUBFINDER_BIN) {
      log('startup', null, 'subfinder not configured (SUBFINDER_BIN not set) — will fall back to amass');
    } else if (!fs.existsSync(SUBFINDER_BIN)) {
      logErr('startup', null, `subfinder configured but NOT found at ${SUBFINDER_BIN}`);
      logErr('startup', null, 'Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest');
      log('startup', null, 'Falling back to amass for all scans');
    } else {
      log('startup', null, `subfinder found ✓ | ${SUBFINDER_BIN} (will be used as primary tool)`);
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
