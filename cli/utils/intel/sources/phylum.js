/**
 * Phylum — paid.
 * https://docs.phylum.io
 *
 * Requires PHYLUM_API_KEY. Phylum surfaces malicious-package telemetry
 * and dependency risk scores via /api/data/packages and /api/data/jobs.
 * Skipped silently when not set.
 */

import { fetchJson } from '../http.js';

const TTL_MS = 6 * 60 * 60 * 1000;

export const name = 'phylum';
export const tier = 'optional';
export const description = 'Phylum supply-chain risk feed (requires PHYLUM_API_KEY)';
export const envKey = 'PHYLUM_API_KEY';

export async function fetchAll() {
  const key = process.env.PHYLUM_API_KEY;
  if (!key) return { skipped: true, reason: 'PHYLUM_API_KEY not set' };

  const headers = { Authorization: `Bearer ${key}` };
  const data = await fetchJson(
    'https://api.phylum.io/api/v0/data/malicious-packages?limit=200',
    { headers, timeout: 20000 },
  );

  const advisories = (data.items || data || []).map(p => ({
    package: p.name,
    ecosystem: p.ecosystem || p.type,
    version: p.version,
    severity: p.severity || 'high',
    summary: p.summary || p.description,
    published: p.published_at || p.created_at,
  }));

  return {
    count: advisories.length,
    advisories,
  };
}

export const TTL = TTL_MS;
