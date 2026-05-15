/**
 * NVD 2.0 — National Vulnerability Database (NIST).
 * https://services.nvd.nist.gov/rest/json/cves/2.0
 *
 * Used for on-demand CVE detail enrichment, not bulk download.
 * Bulk would be 250k+ entries; we let the merger pull only the CVEs that
 * also appear in OSV/GHSA/KEV. With NVD_API_KEY set, rate limit lifts to
 * 50 req / 30s; otherwise 5 req / 30s.
 */

import { fetchJson } from '../http.js';

const BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7d (CVE descriptions don't change often)

export const name = 'nvd';
export const tier = 'core';
export const description = 'NVD 2.0 — CVE detail enrichment (NIST)';

/**
 * Bulk cache build: enrich a list of CVE IDs (typically pulled from KEV +
 * OSV during merge). Returns { details: { CVE-YYYY-NNNN: {...} } }.
 *
 * Respects NVD's 6 req / 30s no-key limit (we sleep 6s between requests).
 * With NVD_API_KEY in env, drops to 600ms.
 */
export async function fetchAll({ cveList = [] } = {}) {
  const apiKey = process.env.NVD_API_KEY;
  const delayMs = apiKey ? 600 : 6000;
  const headers = apiKey ? { apiKey } : {};
  const details = {};

  // Cap to avoid an unbounded job. Caller can pass a smaller list.
  const targets = cveList.slice(0, 500);
  let lastError = null;

  for (const cve of targets) {
    try {
      const res = await fetchJson(`${BASE}?cveId=${encodeURIComponent(cve)}`, { headers });
      const item = res.vulnerabilities?.[0]?.cve;
      if (!item) continue;
      details[cve] = {
        id: item.id,
        published: item.published,
        lastModified: item.lastModified,
        descriptions: (item.descriptions || []).filter(d => d.lang === 'en').map(d => d.value),
        cvss: extractCvss(item.metrics),
        references: (item.references || []).slice(0, 5).map(r => r.url),
        weaknesses: (item.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)),
      };
    } catch (err) {
      lastError = err.message;
    }
    await sleep(delayMs);
  }

  return {
    fetchedCount: Object.keys(details).length,
    requestedCount: targets.length,
    apiKeyUsed: !!apiKey,
    lastError,
    details,
  };
}

function extractCvss(metrics) {
  if (!metrics) return null;
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const v40 = metrics.cvssMetricV40?.[0]?.cvssData;
  const data = v40 || v31;
  if (!data) return null;
  return {
    version: data.version,
    score: data.baseScore,
    severity: data.baseSeverity?.toLowerCase(),
    vector: data.vectorString,
  };
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

export const TTL = TTL_MS;
