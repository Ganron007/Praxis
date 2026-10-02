#!/usr/bin/env node
/**
 * Determinism gate (P-IMP-053).
 *
 * Scans a target twice and compares the *detection* identities produced by each run.
 * A scanner that returns different findings for an unchanged tree is not a scanner you
 * can baseline, gate CI on, or quote a number from — so this asserts the property
 * directly instead of hoping for it.
 *
 * Only detection identity (`file:rule`) is compared, deliberately excluding severity,
 * line numbers and messages: a change in scoring or message wording is not a change in
 * what Praxis found, and failing on it would make the gate noise rather than signal.
 *
 * Usage:
 *   node scripts/check-determinism.mjs [target] [--runs=2] [--timeout=60000]
 *
 * Exit codes:
 *   0  deterministic (identical detection identities across runs)
 *   1  drift detected — the diff is printed
 *   2  the scan itself could not be run
 */

import { spawnSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
// Comparison semantics come from the library, not a copy: the helper that CI relies on
// must be the same one the unit tests cover.
import { diffFindings } from '../cli/utils/scan-fingerprint.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const CLI = path.join(REPO_ROOT, 'cli', 'bin', 'praxis.js');

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const hit = argv.find(a => a.startsWith(`--${name}=`));
  return hit ? hit.split('=')[1] : fallback;
};
const positional = argv.filter(a => !a.startsWith('--'));
const target = positional[0] || '.';
const runs = Math.max(2, parseInt(flag('runs', '2'), 10));
const timeout = parseInt(flag('timeout', '120000'), 10);

function scan(label) {
  process.stderr.write(`  run ${label}…\n`);
  const res = spawnSync(
    process.execPath,
    [CLI, 'scan', 'full', target, '--no-deps', '--no-cache', '--json', '--timeout', String(timeout)],
    { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, cwd: REPO_ROOT }
  );
  if (res.status !== 0) {
    process.stderr.write(`  scan failed (exit ${res.status}): ${(res.stderr || '').slice(-500)}\n`);
    return null;
  }
  // The CLI pretty-prints the JSON object; take from the first brace onward.
  const start = res.stdout.indexOf('{');
  if (start < 0) {
    process.stderr.write('  scan produced no JSON\n');
    return null;
  }
  try {
    return JSON.parse(res.stdout.slice(start));
  } catch (err) {
    process.stderr.write(`  could not parse scan JSON: ${err.message}\n`);
    return null;
  }
}

console.log(`Determinism gate — ${runs} runs over "${target}"\n`);

const results = [];
for (let i = 1; i <= runs; i++) {
  const out = scan(`${i}/${runs}`);
  if (!out) process.exit(2);
  results.push(out);
}

// Fingerprints first: if these differ, a data or runtime change explains any drift.
const fingerprints = results.map(r => r.fingerprint ?? null);
const fpStable = fingerprints.every(f => JSON.stringify(f) === JSON.stringify(fingerprints[0]));
console.log(`\nFingerprint stable across runs: ${fpStable ? 'yes' : 'NO — inputs differ, drift is expected'}`);
for (const f of fingerprints) {
  if (!f) continue;
  const d = f.data || {};
  console.log(`  praxis ${f.tool ?? '?'} · node ${f.node ?? '?'} · probes v${d.probeCorpus?.version ?? '?'}(${d.probeCorpus?.items ?? '?'}) · threatpack v${d.threatPack?.version ?? '?'}(${d.threatPack?.items ?? '?'}) · files ${f.filesScanned ?? '?'}`);
}

const base = results[0].findings || [];
let drifted = false;

for (let i = 1; i < results.length; i++) {
  const { added, removed, common } = diffFindings(base, results[i].findings || []);
  const total = base.length || 1;
  const drift = Math.round(((added.length + removed.length) / total) * 10000) / 100;

  console.log(`\nRun 1 vs run ${i + 1}: ${common} shared identities, ${added.length} added, ${removed.length} removed (${drift}% drift)`);
  if (added.length) {
    console.log('  + appeared:');
    added.slice(0, 20).forEach(x => console.log(`      ${x}`));
    if (added.length > 20) console.log(`      …and ${added.length - 20} more`);
  }
  if (removed.length) {
    console.log('  - disappeared:');
    removed.slice(0, 20).forEach(x => console.log(`      ${x}`));
    if (removed.length > 20) console.log(`      …and ${removed.length - 20} more`);
  }
  if (added.length || removed.length) drifted = true;
}

if (drifted) {
  console.log('\nFAIL — detection is not deterministic for an unchanged tree.');
  console.log('Detection identities must be stable. Investigate before trusting or baselining these numbers.');
  process.exit(1);
}

console.log(`\nPASS — detection identical across ${runs} runs (${base.length} identities).`);