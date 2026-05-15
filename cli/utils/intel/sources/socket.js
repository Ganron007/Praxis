/**
 * Socket.dev — paid.
 * https://docs.socket.dev/reference
 *
 * Requires SOCKET_API_KEY. Best-in-class supply-chain risk scoring for npm
 * (typosquats, install-script risk, dependency drift, malware). Skipped
 * silently when not set.
 *
 * For the merged feed we pull the recent malware advisories list. Live
 * package lookup is exposed via lookupLive() and called by the supply-chain
 * agent during a scan.
 */

import { fetchJson } from '../http.js';

const TTL_MS = 6 * 60 * 60 * 1000; // 6h — Socket updates often

export const name = 'socket';
export const tier = 'optional';
export const description = 'Socket.dev supply-chain risk feed (requires SOCKET_API_KEY)';
export const envKey = 'SOCKET_API_KEY';

function authHeader() {
  const key = process.env.SOCKET_API_KEY;
  if (!key) return null;
  // Socket uses HTTP Basic with the API key as username, blank password
  const b64 = Buffer.from(`${key}:`).toString('base64');
  return { Authorization: `Basic ${b64}` };
}

export async function fetchAll() {
  const headers = authHeader();
  if (!headers) return { skipped: true, reason: 'SOCKET_API_KEY not set' };

  const data = await fetchJson('https://api.socket.dev/v0/threat-feed?limit=200', {
    headers,
    timeout: 20000,
  });

  return {
    count: (data.results || []).length,
    advisories: (data.results || []).map(t => ({
      id: t.id,
      package: t.purl || t.name,
      ecosystem: t.ecosystem,
      severity: t.severity,
      summary: t.summary || t.description,
      published: t.created_at,
      threatType: t.threat_type,
    })),
  };
}

/** Live single-package lookup. Used by supply-chain agent. */
export async function lookupLive(pkg, ecosystem = 'npm') {
  const headers = authHeader();
  if (!headers) return null;
  try {
    const data = await fetchJson(
      `https://api.socket.dev/v0/${ecosystem}/${encodeURIComponent(pkg)}/score`,
      { headers, timeout: 8000, retries: 1 },
    );
    return data;
  } catch {
    return null;
  }
}

export const TTL = TTL_MS;
