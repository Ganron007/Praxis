/**
 * Praxis's own version — the single source of truth.
 * ============================================================================
 *
 * Six modules used to read `package.json` independently for the version, and a
 * seventh (`core/output/sarif.js`) did not read it at all and fell back to a
 * hardcoded `'1.0.0'`. That is six chances to drift at release time and one that
 * reported a confidently wrong number in SARIF provenance.
 *
 * Everything imports `toolVersion()` from here instead. Two consequences worth
 * knowing:
 *
 *   - The value is cached for the process lifetime, so it is cheap to call from
 *     hot paths and cannot change mid-run.
 *   - If the read fails it returns the string `'unknown'` rather than guessing.
 *     A wrong version is worse than an honest one: `cache-manager` keys its cache
 *     on this value, so a stale guess would silently reuse stale findings.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

/** Returned when package.json cannot be read. Never a plausible version string. */
export const UNKNOWN_VERSION = 'unknown';

let cached = null;

/**
 * @returns {string} the Praxis version, or `'unknown'` if it cannot be determined
 */
export function toolVersion() {
  if (cached !== null) return cached;

  try {
    // cli/core/ -> repo root. Resolved from import.meta.url rather than __dirname so it
    // behaves identically on Windows and POSIX.
    const here = path.dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(fs.readFileSync(path.resolve(here, '..', '..', 'package.json'), 'utf8'));
    const version = typeof pkg.version === 'string' ? pkg.version.trim() : '';
    cached = version || UNKNOWN_VERSION;
  } catch {
    cached = UNKNOWN_VERSION;
  }

  return cached;
}

/**
 * True when `a` is a higher version than `b`. Exported because `doctor` needs the same
 * comparison and previously kept its own copy.
 *
 * Returns false for anything unparseable, so an odd version string never produces a
 * spurious "update available".
 */
export function isNewerVersion(candidate, current) {
  const parse = (v) => String(v ?? '').split(/[.+-]/).map((n) => parseInt(n, 10) || 0);
  const a = parse(candidate);
  const b = parse(current);
  if (a.length === 0 || b.length === 0) return false;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d !== 0) return d > 0;
  }
  return false;
}