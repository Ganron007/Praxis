/**
 * Per-source disk cache with TTL.
 *
 * Lives at ~/.praxis/intel/<source>.json. Each entry is wrapped in:
 *   { fetchedAt: ISO string, ttlMs: number, payload: ... }
 *
 * Sources call cache.read('osv') to get the last good payload (or null),
 * and cache.write('osv', data, ttlMs) after a successful fetch.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

// Lazy — resolve home each call so HOME overrides (e.g. in tests) take effect.
const rootDir = () => path.join(os.homedir(), '.praxis', 'intel');

function ensureDir() {
  const dir = rootDir();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function pathFor(source) {
  return path.join(rootDir(), `${source}.json`);
}

export function read(source) {
  try {
    const file = pathFor(source);
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch {
    return null;
  }
}

export function write(source, payload, ttlMs) {
  ensureDir();
  const entry = {
    fetchedAt: new Date().toISOString(),
    ttlMs,
    payload,
  };
  fs.writeFileSync(pathFor(source), JSON.stringify(entry, null, 2));
  return entry;
}

export function isFresh(entry) {
  if (!entry || !entry.fetchedAt || !entry.ttlMs) return false;
  const age = Date.now() - new Date(entry.fetchedAt).getTime();
  return age < entry.ttlMs;
}

export function ageMs(entry) {
  if (!entry || !entry.fetchedAt) return Infinity;
  return Date.now() - new Date(entry.fetchedAt).getTime();
}

export function root() {
  return rootDir();
}
