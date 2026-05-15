/**
 * Snyk Vulnerability DB — paid.
 * https://docs.snyk.io/snyk-api
 *
 * Requires SNYK_TOKEN. Skipped silently when not set.
 * The /rest/orgs/{org_id}/issues endpoint returns issues across an org's
 * monitored projects. We expose a thin pull that grabs recent issues.
 */

import { fetchJson } from '../http.js';

const TTL_MS = 12 * 60 * 60 * 1000;

export const name = 'snyk';
export const tier = 'optional';
export const description = 'Snyk Vulnerability Database (requires SNYK_TOKEN)';
export const envKey = 'SNYK_TOKEN';

export async function fetchAll() {
  const token = process.env.SNYK_TOKEN;
  const orgId = process.env.SNYK_ORG_ID;
  if (!token) return { skipped: true, reason: 'SNYK_TOKEN not set' };
  if (!orgId) return { skipped: true, reason: 'SNYK_ORG_ID not set' };

  const headers = { Authorization: `token ${token}` };
  const url = `https://api.snyk.io/rest/orgs/${orgId}/issues?version=2024-10-15&limit=100`;
  const data = await fetchJson(url, { headers });

  const issues = (data.data || []).map(item => ({
    id: item.id,
    severity: item.attributes?.effective_severity_level,
    title: item.attributes?.title,
    package: item.relationships?.scan_item?.data?.id,
    cves: item.attributes?.problems?.filter(p => p.source === 'CVE').map(p => p.id) || [],
    cvss: item.attributes?.cvss_v3,
    published: item.attributes?.created_at,
  }));

  return {
    orgId,
    count: issues.length,
    issues,
  };
}

export const TTL = TTL_MS;
