/**
 * Intel orchestrator.
 *
 * Public API:
 *   await runUpdate({ onProgress, sources, force })  → MergedReport
 *   loadMerged()                                     → cached merged threat-intel.json
 *   isStale(maxAgeMs)                                → boolean
 *   listSources()                                    → [{ name, tier, description, envKey? }]
 *
 * Cache layout under ~/.praxis/:
 *   intel/<source>.json            per-source TTL'd raw payload
 *   threat-intel.json              merged feed (replaces the legacy seed cache)
 *   intel-meta.json                last update summary
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

import * as cache from './cache.js';
import { mergeIntel, serialize } from './merge.js';

import * as osv from './sources/osv.js';
import * as kev from './sources/kev.js';
import * as epss from './sources/epss.js';
import * as nvd from './sources/nvd.js';
import * as ghsa from './sources/ghsa.js';
import * as gitleaks from './sources/gitleaks.js';
import * as snyk from './sources/snyk.js';
import * as socket from './sources/socket.js';
import * as gitguardian from './sources/gitguardian.js';
import * as sonatype from './sources/sonatype.js';
import * as phylum from './sources/phylum.js';
import * as threatpack from './sources/threatpack.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SEED_PATH = path.resolve(__dirname, '..', '..', 'data', 'threat-intel.json');

// Lazy — resolve at call time so HOME overrides (e.g. in tests) take effect.
const mergedPath = () => path.join(os.homedir(), '.praxis', 'threat-intel.json');
const metaPath = () => path.join(os.homedir(), '.praxis', 'intel-meta.json');

const ALL_SOURCES = [
  osv, ghsa, kev, epss, nvd, gitleaks, threatpack,  // free / core
  snyk, socket, gitguardian, sonatype, phylum,       // optional / paid
];

export function listSources() {
  return ALL_SOURCES.map(s => ({
    name: s.name,
    tier: s.tier,
    description: s.description,
    envKey: s.envKey || null,
  }));
}

/**
 * Run an update across all sources in parallel.
 *
 * @param {object} options
 * @param {(evt: {source, status, message?}) => void} [options.onProgress]
 * @param {string[]} [options.sources]   limit to a subset
 * @param {boolean} [options.force]      ignore TTL on per-source caches
 */
export async function runUpdate(options = {}) {
  const { onProgress = () => {}, sources, force = false } = options;
  const targets = sources
    ? ALL_SOURCES.filter(s => sources.includes(s.name))
    : ALL_SOURCES;

  // First pass: parallel fetch of everything except NVD (NVD needs the
  // CVE list from the others to know what to enrich).
  const firstPass = targets.filter(s => s.name !== 'nvd');
  const firstResults = await Promise.all(
    firstPass.map(s => runOne(s, { force, onProgress }))
  );

  // Second pass: NVD enrichment, using CVEs we just collected.
  let nvdResult = null;
  if (targets.some(s => s.name === 'nvd')) {
    const cveList = collectCves(firstResults);
    nvdResult = await runOne(nvd, { force, onProgress, args: { cveList } });
  }

  const allResults = nvdResult ? [...firstResults, nvdResult] : firstResults;

  // Merge into the unified feed. Start from the existing feed when present
  // so subset updates (--only) don't wipe data owned by other sources.
  let seed = loadSeed();
  try {
    const existing = loadMerged();
    if (existing && typeof existing === 'object') seed = existing;
  } catch { /* corrupt feed — rebuild from bundled seed */ }
  const merged = mergeIntel(seed, allResults);
  const out = serialize(merged);

  ensureHomeDir();
  fs.writeFileSync(mergedPath(), JSON.stringify(out, null, 2));

  const meta = {
    updatedAt: new Date().toISOString(),
    version: out.version,
    sources: out.sources,
  };
  fs.writeFileSync(metaPath(), JSON.stringify(meta, null, 2));

  return { merged: out, meta, results: allResults };
}

async function runOne(source, { force, onProgress, args = {} }) {
  onProgress({ source: source.name, status: 'start' });

  // Cache hit?
  const cached = cache.read(source.name);
  if (!force && cached && cache.isFresh(cached)) {
    onProgress({ source: source.name, status: 'cached' });
    return {
      name: source.name,
      ok: true,
      payload: cached.payload,
      fetchedAt: cached.fetchedAt,
      fromCache: true,
      skipped: cached.payload?.skipped === true,
    };
  }

  try {
    const payload = await source.fetchAll(args);
    if (payload && payload.skipped) {
      // Optional source declined (env var unset, etc.) — record but don't fail.
      cache.write(source.name, payload, source.TTL || 60_000);
      onProgress({ source: source.name, status: 'skipped', message: payload.reason });
      return {
        name: source.name,
        ok: true,
        skipped: true,
        payload,
        fetchedAt: new Date().toISOString(),
      };
    }
    cache.write(source.name, payload, source.TTL || 60_000);
    onProgress({ source: source.name, status: 'ok' });
    return {
      name: source.name,
      ok: true,
      payload,
      fetchedAt: new Date().toISOString(),
      fromCache: false,
    };
  } catch (err) {
    onProgress({ source: source.name, status: 'error', message: err.message });
    // Fall back to whatever's in the cache, even if stale, so a transient
    // outage doesn't blow away our data.
    if (cached) {
      return {
        name: source.name,
        ok: true,
        payload: cached.payload,
        fetchedAt: cached.fetchedAt,
        fromCache: true,
        stale: true,
        error: err.message,
      };
    }
    return {
      name: source.name,
      ok: false,
      error: err.message,
    };
  }
}

function collectCves(results) {
  const cves = new Set();
  for (const r of results) {
    if (!r.ok || r.skipped) continue;
    const p = r.payload;
    if (r.name === 'kev') {
      for (const e of p.entries || []) cves.add(e.cve);
    } else if (r.name === 'osv') {
      for (const rec of p.records || []) {
        for (const c of rec.cves || []) cves.add(c);
      }
    } else if (r.name === 'ghsa') {
      for (const a of p.advisories || []) {
        if (a.cveId) cves.add(a.cveId);
      }
    }
  }
  return [...cves];
}

function loadSeed() {
  try {
    return JSON.parse(fs.readFileSync(SEED_PATH, 'utf-8'));
  } catch {
    return { version: '1.0.0' };
  }
}

function ensureHomeDir() {
  const dir = path.dirname(mergedPath());
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

export function loadMerged() {
  try {
    const p = mergedPath();
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch { /* fall through */ }
  return null;
}

export function loadMeta() {
  try {
    const p = metaPath();
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch { /* fall through */ }
  return null;
}

export function isStale(maxAgeMs) {
  const meta = loadMeta();
  if (!meta || !meta.updatedAt) return true;
  return Date.now() - new Date(meta.updatedAt).getTime() > maxAgeMs;
}

export const PATHS = {
  get MERGED_PATH() { return mergedPath(); },
  get META_PATH() { return metaPath(); },
  SEED_PATH,
};
export const sources = { osv, ghsa, kev, epss, nvd, gitleaks, snyk, socket, gitguardian, sonatype, phylum };
