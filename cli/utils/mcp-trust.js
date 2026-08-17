/**
 * MCP trust registry — known MCP servers with trust scores.
 *
 * Loads cli/data/known-mcps.json (Praxis-curated). The file is integrity-
 * checked against an embedded SHA-256 so a tampered registry degrades
 * gracefully (lookups disabled) instead of silently trusting anything.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REGISTRY_PATH = path.join(__dirname, '..', 'data', 'known-mcps.json');

// SHA-256 of the registry file at curation time. If the file changes,
// update this constant and bump the registry version together.
export const EXPECTED_SHA256 = 'FA88051B0832B9DEDA6A43B1FF370F78A4408C78A9C846E6DE2F27A8169180D1';

let _cache = null;

function load() {
  if (_cache) return _cache;
  try {
    const raw = fs.readFileSync(REGISTRY_PATH, 'utf8');
    const hash = crypto.createHash('sha256').update(raw).digest('hex').toUpperCase();
    const data = JSON.parse(raw);
    _cache = {
      servers: data.servers || {},
      verified: hash === EXPECTED_SHA256,
    };
  } catch {
    _cache = { servers: {}, verified: false };
  }
  return _cache;
}

/**
 * Look up a package name in the trust registry.
 * Returns { tier, trust, note } or { tier: 'unknown', trust: 0 }.
 */
export function lookupTrust(packageName) {
  const { servers, verified } = load();
  if (!verified) return { tier: 'unverified-registry', trust: 0 };
  const entry = servers[packageName];
  if (!entry) return { tier: 'unknown', trust: 0 };
  return { tier: entry.tier, trust: entry.trust, note: entry.note };
}

/** All known package names (for typosquat-distance checks). */
export function listKnown() {
  const { servers } = load();
  return Object.keys(servers);
}

/** Whether the registry file passes its integrity check. */
export function registryIntegrityOk() {
  return load().verified;
}
