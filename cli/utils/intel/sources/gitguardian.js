/**
 * GitGuardian — paid.
 * https://api.gitguardian.com/docs
 *
 * Requires GITGUARDIAN_API_KEY. Provides ~400 secret-detector definitions
 * and a /v1/audit/detectors endpoint listing them. We pull detector
 * definitions to enrich praxis's secret-scanning rule set.
 */

import { fetchJson } from '../http.js';

const TTL_MS = 7 * 24 * 60 * 60 * 1000;

export const name = 'gitguardian';
export const tier = 'optional';
export const description = 'GitGuardian secret detector definitions (requires GITGUARDIAN_API_KEY)';
export const envKey = 'GITGUARDIAN_API_KEY';

export async function fetchAll() {
  const key = process.env.GITGUARDIAN_API_KEY;
  if (!key) return { skipped: true, reason: 'GITGUARDIAN_API_KEY not set' };

  const headers = { Authorization: `Token ${key}` };
  // GitGuardian's public detector list endpoint
  const data = await fetchJson('https://api.gitguardian.com/v1/secret_detectors', { headers });

  const detectors = (Array.isArray(data) ? data : data.results || []).map(d => ({
    id: d.detector_name || d.id,
    family: d.family,
    summary: d.detector_group_name || d.name,
    severity: d.severity || 'high',
  }));

  return {
    count: detectors.length,
    detectors,
  };
}

export const TTL = TTL_MS;
