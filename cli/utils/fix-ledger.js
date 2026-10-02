/**
 * Fix ledger — read the find→fix→verify record for a project.
 * ============================================================================
 *
 * The scanner's stated moat is "find → fix → verify", but the report stops at
 * findings, so the differentiator is only visible in the terminal. `.praxis/fixes.jsonl`
 * already records every applied change (with its verification outcome and the plan
 * needed to reverse it), and `.praxis/failures.jsonl` records every plan that was
 * proposed and *rejected* — which is the more interesting half of the story, since a
 * rejected fix is the loop declining to make a change it cannot justify.
 *
 * Semantics worth stating plainly, because it is easy to misreport:
 *
 *   - `fixes.jsonl` means **currently applied**. `praxis undo` *removes* reverted
 *     entries from the log rather than annotating them, so this module reports no
 *     "undone" count — there is no such data, and inventing one would be a false
 *     negative (the exact failure mode this project keeps refusing to ship).
 *   - An entry is **reversible** when its plan still carries enough information to
 *     undo it: a file creation, an append, or line edits.
 *   - Unreadable or malformed lines are counted, never silently dropped.
 *
 * Everything here is best-effort and never throws: a missing ledger must not break a
 * report, and a broken ledger must not invent activity.
 */

import fs from 'fs';
import path from 'path';

const FIX_LOG = path.join('.praxis', 'fixes.jsonl');
const FAILURE_LOG = path.join('.praxis', 'failures.jsonl');

/**
 * Reads a JSONL log, tolerating absence and malformed lines.
 * @returns {{entries: object[], unreadable: number, error: string|null}}
 */
function readJsonl(absolutePath) {
  let raw;
  try {
    raw = fs.readFileSync(absolutePath, 'utf8');
  } catch (err) {
    const missing = err.code === 'ENOENT';
    return { entries: [], unreadable: 0, error: missing ? null : err.message };
  }

  const entries = [];
  let unreadable = 0;
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') entries.push(parsed);
      else unreadable++;
    } catch {
      unreadable++;
    }
  }
  return { entries, unreadable, error: null };
}

/** True when the plan still carries enough information for `praxis undo` to reverse it. */
export function isReversible(plan) {
  const files = plan?.files;
  if (!Array.isArray(files) || files.length === 0) return false;
  return files.some(fc =>
    fc && (fc.create === true || fc.append !== undefined || Array.isArray(fc.edits) && fc.edits.length > 0)
  );
}

/**
 * Reads the fix ledger for a project.
 *
 * @param {string} rootPath  Project root (the directory containing `.praxis/`).
 * @returns {{
 *   applied: object[], rejected: object[],
 *   appliedUnreadable: number, rejectedUnreadable: number,
 *   error: string|null, hasLog: boolean
 * }}
 */
export function readFixLedger(rootPath = process.cwd()) {
  // Coerce before any path work: `path.join(null, …)` throws a TypeError outside the
  // readJsonl try/catch, which would break the "never throws" contract this module
  // advertises. A missing root falls back to the cwd, which simply yields no ledger.
  const root = typeof rootPath === 'string' && rootPath.length > 0 ? rootPath : process.cwd();

  const fixes = readJsonl(path.join(root, FIX_LOG));
  const failures = readJsonl(path.join(root, FAILURE_LOG));

  return {
    applied: fixes.entries,
    rejected: failures.entries,
    appliedUnreadable: fixes.unreadable,
    rejectedUnreadable: failures.unreadable,
    error: fixes.error || failures.error,
    hasLog: fixes.entries.length > 0 || fixes.error !== null,
  };
}

/** Aggregate counters for the ledger panel. */
export function summarizeFixLedger(ledger) {
  const applied = ledger?.applied || [];
  const rejected = ledger?.rejected || [];

  const verified = applied.filter(e => e.verified === true).length;
  const reversible = applied.filter(e => isReversible(e.plan)).length;

  // Findings addressed by an applied fix. Summed across entries, so a finding fixed in
  // two files counts once per file — that is what the log actually records.
  const findingsFixed = applied.reduce((sum, e) => sum + (Array.isArray(e.findings) ? e.findings.length : 0), 0);

  const rejectedByReason = {};
  for (const r of rejected) {
    const reason = r.reason || 'unknown';
    rejectedByReason[reason] = (rejectedByReason[reason] || 0) + 1;
  }

  return {
    appliedCount: applied.length,
    verified,
    unverified: applied.length - verified,
    reversible,
    irreversible: applied.length - reversible,
    findingsFixed,
    rejectedCount: rejected.length,
    rejectedByReason,
  };
}