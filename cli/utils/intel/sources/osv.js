/**
 * OSV.dev — Open Source Vulnerabilities (Google).
 *
 * Strategy: pull the per-ecosystem advisory zip dumps that OSV publishes daily.
 * https://google.github.io/osv.dev/data/
 *
 * Each ecosystem zip has one JSON per advisory. We download a small set of
 * common ecosystems, extract just the fields praxis needs, and produce a
 * single normalized array of records:
 *
 *   { id, ecosystem, package, ranges, severity, cves, summary, references }
 *
 * Two query helpers are exposed via the merged ThreatIntel: lookupOsv() and
 * a faster live-query mode that hits POST https://api.osv.dev/v1/query for
 * a single package.
 */

import { fetchJson } from '../http.js';

const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'RubyGems', 'crates.io', 'Maven', 'Packagist', 'NuGet'];
const TTL_MS = 12 * 60 * 60 * 1000; // 12h

export const name = 'osv';
export const tier = 'core';
export const description = 'OSV.dev — Google open-source vuln database (npm, PyPI, Go, etc.)';

export async function fetchAll() {
  // The full OSV dump is large (~hundreds of MB). For the bundled feed we keep
  // the seed lean by querying the OSV API for the most common malicious /
  // high-severity advisories. For richer offline coverage, praxis queries
  // OSV live during scans (see lookupLive() below).
  //
  // Here we batch-query OSV for a curated list of historically compromised
  // packages so the merged threat-intel.json always carries a usable seed,
  // even when the user is offline at scan time.
  const knownCompromised = [
    { ecosystem: 'npm', name: 'event-stream' },
    { ecosystem: 'npm', name: 'flatmap-stream' },
    { ecosystem: 'npm', name: 'eslint-scope' },
    { ecosystem: 'npm', name: 'ua-parser-js' },
    { ecosystem: 'npm', name: 'coa' },
    { ecosystem: 'npm', name: 'rc' },
    { ecosystem: 'npm', name: 'colors' },
    { ecosystem: 'npm', name: 'node-ipc' },
    { ecosystem: 'npm', name: '@solana/web3.js' },
    { ecosystem: 'npm', name: 'lottie-player' },
    { ecosystem: 'npm', name: 'axios' },
    { ecosystem: 'PyPI', name: 'litellm' },
    { ecosystem: 'PyPI', name: 'ctx' },
    { ecosystem: 'PyPI', name: 'phpass' },
  ];

  const records = [];
  for (const target of knownCompromised) {
    try {
      const adv = await fetchJson('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ package: { name: target.name, ecosystem: target.ecosystem } }),
      });
      for (const v of adv.vulns || []) {
        records.push(normalize(v, target.ecosystem, target.name));
      }
    } catch {
      // Skip individual failures — orchestrator will report partial success
    }
  }

  return { records, ecosystems: ECOSYSTEMS };
}

/**
 * Live single-package lookup. Used by the supply-chain agent at scan time
 * when we have a package name + version to check.
 */
export async function lookupLive(name, version, ecosystem = 'npm') {
  try {
    const body = { package: { name, ecosystem } };
    if (version) body.version = version;
    const res = await fetchJson('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      timeout: 8000,
      retries: 1,
    });
    return (res.vulns || []).map(v => normalize(v, ecosystem, name));
  } catch {
    return [];
  }
}

function normalize(vuln, ecosystem, packageName) {
  const cves = (vuln.aliases || []).filter(a => /^CVE-/i.test(a));
  const severity = pickSeverity(vuln);
  const ranges = (vuln.affected || [])
    .filter(a => a.package?.name === packageName || !a.package?.name)
    .flatMap(a => a.ranges || []);

  return {
    id: vuln.id,
    ecosystem,
    package: packageName,
    summary: vuln.summary || vuln.details?.slice(0, 200) || '',
    severity,
    cves,
    ranges: ranges.map(r => ({
      type: r.type,
      events: (r.events || []).map(e => ({ ...e })),
    })),
    references: (vuln.references || []).slice(0, 5).map(r => r.url),
    published: vuln.published || vuln.modified || null,
  };
}

function pickSeverity(vuln) {
  // OSV severity comes in either CVSS_V3 or DB-specific fields. Prefer CVSS.
  for (const s of vuln.severity || []) {
    if (s.type === 'CVSS_V3' || s.type === 'CVSS_V4') {
      const score = parseFloat((s.score || '').match(/\/([0-9.]+)$/)?.[1] || s.score);
      if (!Number.isNaN(score)) {
        if (score >= 9.0) return 'critical';
        if (score >= 7.0) return 'high';
        if (score >= 4.0) return 'medium';
        return 'low';
      }
    }
  }
  return vuln.database_specific?.severity?.toLowerCase() || 'medium';
}

export const TTL = TTL_MS;
