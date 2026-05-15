/**
 * Sonatype OSS Index — free with low rate limits, paid for higher volume.
 * https://ossindex.sonatype.org/rest
 *
 * Optional auth via SONATYPE_USER + SONATYPE_TOKEN raises the limit.
 * Operates per-batch component lookup (POST /api/v3/component-report).
 * For the merged feed we fetch a small recent-vulns sample; primary use
 * is the lookupLive() helper at scan time.
 */

import { fetchJson } from '../http.js';

const TTL_MS = 12 * 60 * 60 * 1000;

export const name = 'sonatype';
export const tier = 'optional';
export const description = 'Sonatype OSS Index (anonymous works; SONATYPE_USER/TOKEN raises limits)';
export const envKey = 'SONATYPE_USER';

function authHeader() {
  const user = process.env.SONATYPE_USER;
  const token = process.env.SONATYPE_TOKEN;
  if (!user || !token) return null;
  const b64 = Buffer.from(`${user}:${token}`).toString('base64');
  return { Authorization: `Basic ${b64}` };
}

export async function fetchAll() {
  // Default seed: query a known-noisy set so users get sample data without
  // configuring credentials. This is the only source where a no-key call
  // still yields useful seed records.
  const headers = { 'content-type': 'application/json', ...(authHeader() || {}) };
  const seed = ['pkg:npm/lodash@4.17.20', 'pkg:npm/axios@0.21.0', 'pkg:pypi/requests@2.19.0'];

  try {
    const data = await fetchJson('https://ossindex.sonatype.org/api/v3/component-report', {
      method: 'POST',
      headers,
      body: JSON.stringify({ coordinates: seed }),
      timeout: 15000,
    });
    const advisories = (Array.isArray(data) ? data : []).flatMap(report =>
      (report.vulnerabilities || []).map(v => ({
        purl: report.coordinates,
        cve: (v.cve || v.id),
        cvssScore: v.cvssScore,
        cvssVector: v.cvssVector,
        title: v.title,
        description: v.description?.slice(0, 200),
        reference: v.reference,
      }))
    );

    return {
      authed: !!authHeader(),
      count: advisories.length,
      advisories,
    };
  } catch (err) {
    if (!authHeader()) {
      return { skipped: true, reason: `Anonymous query failed (${err.message}). Set SONATYPE_USER/TOKEN.` };
    }
    throw err;
  }
}

/** Live PURL lookup for use in scan-time enrichment. */
export async function lookupLive(purls = []) {
  const headers = { 'content-type': 'application/json', ...(authHeader() || {}) };
  if (!purls.length) return [];
  try {
    return await fetchJson('https://ossindex.sonatype.org/api/v3/component-report', {
      method: 'POST',
      headers,
      body: JSON.stringify({ coordinates: purls.slice(0, 128) }),
      timeout: 12000,
      retries: 1,
    });
  } catch {
    return [];
  }
}

export const TTL = TTL_MS;
