/**
 * Tests for the multi-source threat-intel module.
 *
 * No network calls — `fetch` is monkey-patched per test so we can validate
 * cache, merge, and source-parser behavior deterministically.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

// =============================================================================
// fetch mock harness
// =============================================================================

const realFetch = global.fetch;
let fetchHandlers = []; // [{ match: (url) => bool, response: () => Response }]

function mockFetch() {
  global.fetch = async (url, opts) => {
    for (const h of fetchHandlers) {
      if (h.match(url, opts)) return h.response(url, opts);
    }
    throw new Error(`unmocked fetch: ${url}`);
  };
}
function restoreFetch() {
  global.fetch = realFetch;
}
function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

// Re-route ~/.praxis to a tmpdir so tests don't pollute the user's home.
let tmpHome;
function redirectHome() {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-intel-test-'));
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
}
function restoreHome() {
  try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* */ }
}

// =============================================================================
// cache.js
// =============================================================================

describe('intel cache', async () => {
  before(redirectHome);
  after(restoreHome);

  const cache = await import('../utils/intel/cache.js');

  it('writes and reads a payload', () => {
    cache.write('mock', { a: 1 }, 60_000);
    const entry = cache.read('mock');
    assert.equal(entry.payload.a, 1);
    assert.ok(entry.fetchedAt);
    assert.equal(entry.ttlMs, 60_000);
  });

  it('isFresh respects TTL', async () => {
    const entry = cache.write('mock-ttl', { x: 1 }, 50);
    assert.equal(cache.isFresh(entry), true);
    await new Promise(r => setTimeout(r, 70));
    assert.equal(cache.isFresh(cache.read('mock-ttl')), false);
  });

  it('returns null for missing source', () => {
    assert.equal(cache.read('does-not-exist'), null);
  });
});

// =============================================================================
// merge.js
// =============================================================================

describe('intel merge', async () => {
  const { mergeIntel, serialize } = await import('../utils/intel/merge.js');

  const seed = {
    version: '1.0.0',
    maliciousSkillHashes: [],
    compromisedMcpServers: [],
    maliciousConfigSignatures: [],
    knownVulnerableConfigs: [],
  };

  it('bumps version and timestamps the merge', () => {
    const merged = mergeIntel(seed, []);
    assert.equal(merged.version, '1.0.1');
    assert.ok(new Date(merged.updated).getTime() > 0);
  });

  it('builds osvIndex and cveAdvisories from OSV records', () => {
    const merged = mergeIntel(seed, [{
      name: 'osv', ok: true, fetchedAt: new Date().toISOString(),
      payload: {
        records: [{
          id: 'GHSA-xxx', ecosystem: 'npm', package: 'foo',
          summary: 'Bad', severity: 'high', cves: ['CVE-2099-9999'],
          ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.5.0' }] }],
          references: [],
        }],
      },
    }]);
    assert.ok(merged.osvIndex['npm/foo']);
    assert.equal(merged.osvIndex['npm/foo'][0].package, 'foo');
    assert.equal(merged.cveAdvisories.length, 1);
    assert.equal(merged.cveAdvisories[0].cve, 'CVE-2099-9999');
  });

  it('flattens KEV and EPSS feeds', () => {
    const merged = mergeIntel(seed, [
      {
        name: 'kev', ok: true, fetchedAt: new Date().toISOString(),
        payload: { catalogVersion: '2026.04.01', entries: [{ cve: 'CVE-2099-1' }, { cve: 'CVE-2099-2' }] },
      },
      {
        name: 'epss', ok: true, fetchedAt: new Date().toISOString(),
        payload: { modelDate: '2026-04-01', scores: { 'CVE-2099-1': { score: 0.9, percentile: 0.99 } } },
      },
    ]);
    assert.deepEqual(merged.kevList, ['CVE-2099-1', 'CVE-2099-2']);
    assert.equal(merged.epssScores['CVE-2099-1'].score, 0.9);
  });

  it('records skipped sources without erroring', () => {
    const merged = mergeIntel(seed, [{
      name: 'snyk', ok: true, skipped: true,
      payload: { skipped: true, reason: 'SNYK_TOKEN not set' },
    }]);
    assert.equal(merged.sources.snyk.skipped, true);
    assert.equal(merged.sources.snyk.reason, 'SNYK_TOKEN not set');
  });

  it('strips internal seen-set on serialize', () => {
    const merged = mergeIntel(seed, [{
      name: 'osv', ok: true,
      payload: { records: [{ id: 'A', ecosystem: 'npm', package: 'x', cves: ['CVE-1'], ranges: [] }] },
    }]);
    const out = serialize(merged);
    assert.equal(out._cveAdvisorySeen, undefined);
  });
});

// =============================================================================
// OSV parser (normalize + version range)
// =============================================================================

describe('OSV source', async () => {
  before(() => { redirectHome(); mockFetch(); });
  after(() => { restoreHome(); restoreFetch(); });
  beforeEach(() => { fetchHandlers = []; });

  const osv = await import('../utils/intel/sources/osv.js');

  it('lookupLive returns normalized records', async () => {
    fetchHandlers.push({
      match: (url) => String(url).includes('osv.dev/v1/query'),
      response: () => jsonResponse({
        vulns: [{
          id: 'GHSA-aaa-bbb-ccc',
          summary: 'Critical RCE',
          aliases: ['CVE-2099-1234'],
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8' }],
          affected: [{
            package: { name: 'foo', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.5.0' }] }],
          }],
        }],
      }),
    });

    const recs = await osv.lookupLive('foo', '1.2.3', 'npm');
    assert.equal(recs.length, 1);
    assert.equal(recs[0].cves[0], 'CVE-2099-1234');
    assert.equal(recs[0].severity, 'critical');
    assert.equal(recs[0].package, 'foo');
  });

  it('returns [] when fetch errors', async () => {
    fetchHandlers.push({
      match: () => true,
      response: () => { throw new Error('network'); },
    });
    const recs = await osv.lookupLive('foo', '1.0.0', 'npm');
    assert.deepEqual(recs, []);
  });
});

// =============================================================================
// ThreatIntel.lookupOsv (version range matching)
// =============================================================================

describe('ThreatIntel.lookupOsv', async () => {
  before(redirectHome);
  after(restoreHome);

  it('marks affected/non-affected by version', async () => {
    // Write a hand-crafted merged feed and verify range eval.
    const merged = {
      version: '1.0.1',
      osvIndex: {
        'npm/foo': [{
          id: 'X', ecosystem: 'npm', package: 'foo', cves: ['CVE-1'],
          severity: 'high', ranges: [
            { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.5.0' }] },
          ],
        }],
      },
    };
    const merged_path = path.join(tmpHome, '.praxis', 'threat-intel.json');
    fs.mkdirSync(path.dirname(merged_path), { recursive: true });
    fs.writeFileSync(merged_path, JSON.stringify(merged));

    const { ThreatIntel } = await import('../utils/threat-intel.js');
    ThreatIntel._resetCache();

    const affected = ThreatIntel.lookupOsv('foo', '1.2.0', 'npm');
    assert.equal(affected[0].isAffected, true);

    const safe = ThreatIntel.lookupOsv('foo', '1.5.0', 'npm');
    assert.equal(safe[0].isAffected, false);
  });
});

// =============================================================================
// strict-intel CI staleness check
// =============================================================================

describe('intel staleness', async () => {
  before(redirectHome);
  after(restoreHome);

  it('isStale returns true when no metadata exists', async () => {
    const intel = await import('../utils/intel/index.js');
    assert.equal(intel.isStale(60_000), true);
  });

  it('isStale respects updatedAt', async () => {
    fs.mkdirSync(path.join(tmpHome, '.praxis'), { recursive: true });
    // Write with an old timestamp so any threshold under that age triggers stale.
    const tenMinAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    fs.writeFileSync(
      path.join(tmpHome, '.praxis', 'intel-meta.json'),
      JSON.stringify({ updatedAt: tenMinAgo, sources: {} })
    );
    const intel = await import('../utils/intel/index.js');
    assert.equal(intel.isStale(60 * 60 * 1000), false); // 1h threshold → fresh
    assert.equal(intel.isStale(60 * 1000), true);       // 1min threshold → stale
  });
});

// =============================================================================
// Gitleaks TOML parser
// =============================================================================

describe('Gitleaks parser', async () => {
  before(() => { redirectHome(); mockFetch(); });
  after(() => { restoreHome(); restoreFetch(); });

  it('parses [[rules]] sections with single-line and multi-line regex', async () => {
    const toml = `
[[rules]]
id = "aws-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws"]

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = '''ghp_[a-zA-Z0-9]{36}'''
`;
    fetchHandlers = [{
      match: (url) => String(url).includes('gitleaks.toml'),
      response: () => new Response(toml, { status: 200, headers: { 'content-type': 'text/plain' } }),
    }];
    const gitleaks = await import('../utils/intel/sources/gitleaks.js');
    const result = await gitleaks.fetchAll();
    assert.equal(result.count, 2);
    assert.equal(result.rules[0].id, 'aws-key');
    assert.match(result.rules[0].regex, /AKIA/);
  });
});
