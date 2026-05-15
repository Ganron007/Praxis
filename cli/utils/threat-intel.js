/**
 * Threat Intelligence Feed
 * =========================
 *
 * Loads and queries Praxis's threat intelligence database.
 *
 * Data sources (merged by `cli/utils/intel/`):
 *   - OSV.dev               package advisories (npm, PyPI, Go, ...)
 *   - GitHub Advisory DB    cross-ecosystem advisories
 *   - CISA KEV              actively-exploited CVEs
 *   - EPSS                  exploit-likelihood scores
 *   - NVD                   CVE detail enrichment
 *   - Gitleaks rules        extra secret-detection patterns
 *   - Snyk / Socket / GitGuardian / Sonatype / Phylum   (paid, optional)
 *
 * Bundled-seed fields (maliciousSkillHashes, compromisedMcpServers,
 * maliciousConfigSignatures) are loaded from `cli/data/threat-intel.json`
 * when no merged feed is on disk yet.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';
import * as intel from './intel/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SEED_PATH = path.resolve(__dirname, '..', 'data', 'threat-intel.json');
const mergedFeedPath = () => path.join(os.homedir(), '.praxis', 'threat-intel.json');

let _cache = null;

export class ThreatIntel {
  /**
   * Load threat intel data.
   *
   * Resolution order:
   *   1. Merged multi-source feed at ~/.praxis/threat-intel.json (if present)
   *   2. Bundled seed at cli/data/threat-intel.json
   */
  static load() {
    if (_cache) return _cache;

    let data = null;

    try {
      if (fs.existsSync(mergedFeedPath())) {
        data = JSON.parse(fs.readFileSync(mergedFeedPath(), 'utf-8'));
      }
    } catch { /* fall through to seed */ }

    if (!data) {
      try {
        data = JSON.parse(fs.readFileSync(SEED_PATH, 'utf-8'));
      } catch {
        data = emptyFeed();
      }
    }

    // Ensure new fields exist even when reading the old seed.
    data.cveAdvisories ||= [];
    data.kevList ||= [];
    data.kevDetails ||= {};
    data.epssScores ||= {};
    data.osvIndex ||= {};
    data.ghsaIndex ||= {};
    data.nvdDetails ||= {};
    data.secretRules ||= [];

    _cache = data;
    return data;
  }

  /** @internal — for tests */
  static _resetCache() { _cache = null; }

  // ---- Legacy API (unchanged) ---------------------------------------------

  static lookupHash(sha256) {
    const data = ThreatIntel.load();
    return (data.maliciousSkillHashes || []).find(h => h.sha256 === sha256) || null;
  }

  static lookupMcpServer(name, version = '*') {
    const data = ThreatIntel.load();
    return (data.compromisedMcpServers || []).find(s => {
      if (s.name !== name) return false;
      if (s.versions.includes('*')) return true;
      return s.versions.some(v => {
        if (v.startsWith('<')) return version < v.slice(1);
        return v === version;
      });
    }) || null;
  }

  static matchSignatures(content) {
    const data = ThreatIntel.load();
    const matches = [];
    for (const sig of data.maliciousConfigSignatures || []) {
      try {
        const re = new RegExp(sig.pattern, 'gi');
        if (re.test(content)) matches.push(sig);
      } catch { /* skip bad patterns */ }
    }
    return matches;
  }

  static hash(content) {
    return createHash('sha256').update(content).digest('hex');
  }

  // ---- New: multi-source query API ----------------------------------------

  /**
   * Look up advisories for a package version. Checks the merged OSV index
   * first; affected version ranges are evaluated naively (any match in
   * the package's advisories is returned with isAffected=true|false).
   *
   * @param {string} pkg
   * @param {string} version
   * @param {string} ecosystem  'npm', 'PyPI', 'Go', etc.
   */
  static lookupOsv(pkg, version, ecosystem = 'npm') {
    const data = ThreatIntel.load();
    const advisories = data.osvIndex[`${ecosystem}/${pkg}`] || [];
    return advisories.map(a => ({
      ...a,
      isAffected: version ? versionInRanges(version, a.ranges) : null,
    }));
  }

  /** Look up GHSA advisories for a package. */
  static lookupGhsa(pkg, ecosystem = 'npm') {
    const data = ThreatIntel.load();
    return data.ghsaIndex[`${ecosystem}/${pkg}`] || [];
  }

  /** EPSS exploit-likelihood for a CVE. Returns null if unknown. */
  static getEpss(cve) {
    const data = ThreatIntel.load();
    return data.epssScores[cve] || null;
  }

  /** True if a CVE is in CISA KEV (actively exploited). */
  static isInKev(cve) {
    const data = ThreatIntel.load();
    return Array.isArray(data.kevList) && data.kevList.includes(cve);
  }

  static getKevDetails(cve) {
    const data = ThreatIntel.load();
    return data.kevDetails?.[cve] || null;
  }

  /** Full NVD record for a CVE if previously enriched. */
  static getNvdDetail(cve) {
    const data = ThreatIntel.load();
    return data.nvdDetails[cve] || null;
  }

  /**
   * Extra secret detection regexes pulled from Gitleaks / GitGuardian.
   * The scanner can merge these with its hardcoded SECRET_PATTERNS.
   */
  static getExtraSecretRules() {
    const data = ThreatIntel.load();
    return data.secretRules || [];
  }

  // ---- Update / freshness -------------------------------------------------

  /**
   * Run a multi-source threat-intel update.
   *
   * @param {object} [options]   forwarded to `intel.runUpdate`
   *                             ({ sources, force, onProgress })
   */
  static async update(options = {}) {
    const result = await intel.runUpdate(options);
    _cache = null; // force re-read on next load()
    return {
      updated: true,
      version: result.merged.version,
      sources: result.meta.sources,
    };
  }

  /** True if the merged feed is older than `maxAgeMs`. */
  static isStale(maxAgeMs) {
    return intel.isStale(maxAgeMs);
  }

  static stats() {
    const data = ThreatIntel.load();
    return {
      version: data.version,
      updated: data.updated,
      hashes: data.maliciousSkillHashes?.length || 0,
      servers: data.compromisedMcpServers?.length || 0,
      signatures: data.maliciousConfigSignatures?.length || 0,
      configs: data.knownVulnerableConfigs?.length || 0,
      cveAdvisories: (data.cveAdvisories || []).length,
      kevEntries: (data.kevList || []).length,
      epssScores: Object.keys(data.epssScores || {}).length,
      nvdDetails: Object.keys(data.nvdDetails || {}).length,
      extraSecretRules: (data.secretRules || []).length,
      sources: data.sources || null,
    };
  }
}

function emptyFeed() {
  return {
    version: '0.0.0',
    maliciousSkillHashes: [],
    compromisedMcpServers: [],
    maliciousConfigSignatures: [],
    knownVulnerableConfigs: [],
    cveAdvisories: [],
    kevList: [],
    kevDetails: {},
    epssScores: {},
    osvIndex: {},
    ghsaIndex: {},
    nvdDetails: {},
    secretRules: [],
  };
}

/**
 * Naive evaluation of OSV "ranges" against a version. OSV's range model is
 * { type: 'SEMVER'|'ECOSYSTEM'|'GIT', events: [{introduced}, {fixed}] }.
 * We compare numerically for the SEMVER case and string-equal for fixed
 * versions otherwise. A null/empty range list returns true (assume affected).
 */
function versionInRanges(version, ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) return true;
  for (const r of ranges) {
    let introduced = '0';
    let fixed = null;
    for (const evt of r.events || []) {
      if (evt.introduced) introduced = evt.introduced;
      if (evt.fixed) fixed = evt.fixed;
    }
    if (compareSemver(version, introduced) >= 0) {
      if (!fixed) return true;
      if (compareSemver(version, fixed) < 0) return true;
    }
  }
  return false;
}

function compareSemver(a, b) {
  const pa = String(a).split('.').map(p => parseInt(p, 10) || 0);
  const pb = String(b).split('.').map(p => parseInt(p, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] || 0;
    const db = pb[i] || 0;
    if (da !== db) return da - db;
  }
  return 0;
}
