// node --test  — pins the upsert merge a subdomain rescan does before writing
// CTEMData. Pure function, no Mongo, no scanners.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mergeSubdomainResults, hostKey, belongsToDomain } = require('../index.js');

const by = (list) => Object.fromEntries(list.map((e) => [e.sub, e]));

test('hostKey keeps www., belongsToDomain ignores it', () => {
  assert.equal(hostKey('WWW.Acme.Test.'), 'www.acme.test');
  assert.equal(belongsToDomain('www.acme.test', 'acme.test'), true);
  assert.equal(belongsToDomain('acme.test', 'www.acme.test'), true);
  assert.equal(belongsToDomain('acme.testing', 'acme.test'), false);
});

test('rescan upserts: updates found entries, keeps unfound ones, creates new ones, leaves other domains alone', () => {
  const existing = [
    { _id: 'id-www', sub: 'www.acme.test', ip: '10.0.0.1', status: 'Active', assetCriticality: 'High', ownerEmail: 'o@acme.test', source: 'scan', sslGrade: 'A', sslDaysRemaining: 40 },
    { _id: 'id-vpn', sub: 'vpn.acme.test', ip: '', status: 'Pending', source: 'client-request', addedAt: new Date('2026-09-01'), addedBy: 'admin@x' },
    { _id: 'id-old', sub: 'old.acme.test', ip: '10.0.0.9', status: 'Active', source: 'scan' },
    { _id: 'id-shop', sub: 'shop.acme.co', ip: '10.5.5.5', status: 'Active', source: 'scan' },
    { _id: 'id-un', sub: 'lonely.other.net', ip: '', status: 'Pending', source: 'manual', rootDomain: '' },
  ];
  const scanned = [
    { sub: 'www.acme.test', ip: '10.9.9.9', status: 'Active', assetCriticality: 'Low', sslGrade: 'N/A', sslDaysRemaining: null },
    { sub: 'new.acme.test', ip: '10.1.1.1', status: 'Active', assetCriticality: 'Low', sslGrade: 'N/A', sslDaysRemaining: null },
    { sub: 'noip.acme.test', ip: '', status: 'Active', assetCriticality: 'Low', sslGrade: 'N/A', sslDaysRemaining: null },
    { sub: 'new.acme.test', ip: '10.1.1.1' }, // scanner repeated a name
  ];
  const r = mergeSubdomainResults(existing, scanned, 'acme.test');
  assert.deepEqual({ kept: r.kept, updated: r.updated, created: r.created, retained: r.retained }, { kept: 2, updated: 1, created: 2, retained: 2 });
  const m = by(r.merged);
  assert.equal(r.merged.length, 7);

  // found again → fresh ip, admin-owned + SSL + _id preserved, criticality NOT reset to Low
  assert.equal(m['www.acme.test'].ip, '10.9.9.9');
  assert.equal(m['www.acme.test']._id, 'id-www');
  assert.equal(m['www.acme.test'].assetCriticality, 'High');
  assert.equal(m['www.acme.test'].ownerEmail, 'o@acme.test');
  assert.equal(m['www.acme.test'].sslGrade, 'A');
  assert.equal(m['www.acme.test'].sslDaysRemaining, 40);
  assert.equal(m['www.acme.test'].rootDomain, 'acme.test');

  // not found this run → kept exactly as it was (the client-requested one and the stale scan one)
  assert.deepEqual(m['vpn.acme.test'], existing[1]);
  assert.deepEqual(m['old.acme.test'], existing[2]);

  // new → created as a scan entry
  assert.equal(m['new.acme.test'].source, 'scan');
  assert.ok(m['new.acme.test'].addedAt instanceof Date);
  assert.equal(m['new.acme.test'].rootDomain, 'acme.test');

  // no IP → Inactive, not blindly Active
  assert.equal(m['noip.acme.test'].status, 'Inactive');

  // other root domain and Unassigned entries untouched
  assert.deepEqual(m['shop.acme.co'], existing[3]);
  assert.deepEqual(m['lonely.other.net'], existing[4]);
});

test('www.acme.test and acme.test are distinct entries', () => {
  const existing = [
    { sub: 'acme.test', ip: '1.1.1.1', status: 'Active', assetCriticality: 'Critical', source: 'scan' },
    { sub: 'www.acme.test', ip: '1.1.1.2', status: 'Active', assetCriticality: 'Low', source: 'scan' },
  ];
  const scanned = [{ sub: 'acme.test', ip: '1.1.1.1' }, { sub: 'www.acme.test', ip: '1.1.1.2' }];
  const m = by(mergeSubdomainResults(existing, scanned, 'acme.test').merged);
  assert.equal(m['acme.test'].assetCriticality, 'Critical');
  assert.equal(m['www.acme.test'].assetCriticality, 'Low');
});

test('an Unassigned entry that a later root-domain scan finds is attributed to that domain', () => {
  const existing = [{ sub: 'api.acme.test', ip: '', status: 'Pending', source: 'client-request', rootDomain: '' }];
  const r = mergeSubdomainResults(existing, [{ sub: 'api.acme.test', ip: '2.2.2.2' }], 'acme.test');
  assert.equal(r.updated, 1);
  assert.equal(r.merged[0].rootDomain, 'acme.test');
  assert.equal(r.merged[0].source, 'client-request');
  assert.equal(r.merged[0].status, 'Active');
});

test('first scan on an empty tenant just creates', () => {
  const r = mergeSubdomainResults(undefined, [{ sub: 'a.acme.test', ip: '1.1.1.1' }], 'acme.test');
  assert.equal(r.created, 1);
  assert.equal(r.merged.length, 1);
});
