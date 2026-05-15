/**
 * Error handling helpers
 * ======================
 *
 * Replacement for the ~124 silent `try { ... } catch { /* skip *\/ }`
 * blocks scattered across the codebase. Errors are no longer invisible:
 * they surface under `--verbose` (or when `PRAXIS_DEBUG=1`).
 */

import * as output from '../utils/output.js';

const DEBUG = process.env.PRAXIS_DEBUG === '1' || process.env.PRAXIS_DEBUG === '1';

/**
 * Run `fn`, return its result, and on throw return `fallback` instead.
 * Optionally logs the error under verbose/debug mode so it stops being
 * invisible.
 *
 *   const config = safeCatch(() => JSON.parse(raw), {}, { ctx: 'config' });
 */
export function safeCatch(fn, fallback, options = {}) {
  const { ctx = 'unknown', verbose = false } = options;
  try {
    return fn();
  } catch (err) {
    if (DEBUG || verbose) {
      output.warning(`[${ctx}] swallowed: ${err.message}`);
    }
    return fallback;
  }
}

/**
 * Async variant.
 */
export async function safeCatchAsync(fn, fallback, options = {}) {
  const { ctx = 'unknown', verbose = false } = options;
  try {
    return await fn();
  } catch (err) {
    if (DEBUG || verbose) {
      output.warning(`[${ctx}] swallowed: ${err.message}`);
    }
    return fallback;
  }
}

/**
 * Convert any value into an Error so callers can rely on `.message` and
 * `.stack`. Useful at boundaries (catch arms with `catch (e)` where `e`
 * may be a string).
 */
export function toError(value) {
  if (value instanceof Error) return value;
  if (typeof value === 'string') return new Error(value);
  try {
    return new Error(JSON.stringify(value));
  } catch {
    return new Error(String(value));
  }
}
