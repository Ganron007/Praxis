/**
 * GitHub Security Advisories (GHSA).
 * https://docs.github.com/en/rest/security-advisories/global-advisories
 *
 * REST endpoint, paginated, returns published advisories across all
 * ecosystems. Auth optional (GITHUB_TOKEN raises rate limit from 60 to
 * 5000 req/h). We pull the latest 1000 advisories — newer than KEV adds,
 * captures advisories that may not yet be in OSV.
 */

import { fetchJson, safeFetch } from '../http.js';

const BASE = 'https://api.github.com/advisories';
const PER_PAGE = 100;
const MAX_PAGES = 10;
const TTL_MS = 12 * 60 * 60 * 1000; // 12h

export const name = 'ghsa';
export const tier = 'core';
export const description = 'GitHub Security Advisories (global)';

export async function fetchAll() {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const advisories = [];
  let url = `${BASE}?per_page=${PER_PAGE}&type=reviewed&sort=published&direction=desc`;

  for (let page = 0; page < MAX_PAGES && url; page++) {
    const res = await safeFetch(url, { headers });
    if (!res.ok) {
      if (page === 0) throw new Error(`HTTP ${res.status} from GHSA`);
      break;
    }
    const data = await res.json();
    for (const adv of data) {
      advisories.push(normalize(adv));
    }
    url = parseNextLink(res.headers.get('link')) || null;
  }

  return {
    tokenUsed: !!token,
    count: advisories.length,
    advisories,
  };
}

function normalize(adv) {
  return {
    ghsaId: adv.ghsa_id,
    cveId: adv.cve_id,
    summary: adv.summary,
    severity: adv.severity, // critical / high / moderate / low
    published: adv.published_at,
    updated: adv.updated_at,
    cwes: (adv.cwes || []).map(c => c.cwe_id),
    references: (adv.references || []).slice(0, 5).map(r => r.url || r),
    vulnerabilities: (adv.vulnerabilities || []).map(v => ({
      ecosystem: v.package?.ecosystem,
      package: v.package?.name,
      vulnerable_version_range: v.vulnerable_version_range,
      first_patched_version: v.first_patched_version,
    })),
  };
}

function parseNextLink(linkHeader) {
  if (!linkHeader) return null;
  for (const part of linkHeader.split(',')) {
    const m = part.match(/<([^>]+)>;\s*rel="next"/);
    if (m) return m[1];
  }
  return null;
}

export const TTL = TTL_MS;
