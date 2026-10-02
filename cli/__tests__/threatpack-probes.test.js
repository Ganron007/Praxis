/**
 * Threat-pack probe precision (P-IMP-057).
 *
 * A shipped threat-pack probe fired a *medium-severity* "document-payload split
 * injection" finding on the phrase "when combined with" — idiomatic English that
 * appears in ordinary code comments. A scanner that reports a medium-severity
 * security finding on a comment about stdout is a credibility problem, and this
 * file exists so that precision cannot silently regress.
 *
 * Two things are pinned:
 *   1. TP-003 requires an actual chaining referent, and does not fire on ordinary prose.
 *   2. Every shipped threat-pack probe compiles through the real compiler, which
 *      enforces the ReDoS guard — so a pattern change cannot smuggle in a
 *      catastrophic-backtracking construct.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { _internals } from '../agents/prompt-injection-prober.js';

const PACK_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', 'cli', 'data', 'threatpacks', 'latest.json'
);
const pack = JSON.parse(fs.readFileSync(PACK_PATH, 'utf8'));

describe('threat-pack probes — compile safety', () => {
  it('ships a non-empty probe set', () => {
    assert.ok(Array.isArray(pack.probes) && pack.probes.length > 0);
  });

  it('every probe compiles through the real compiler (ReDoS guard enforced)', () => {
    for (const probe of pack.probes) {
      assert.doesNotThrow(
        () => _internals.compileProbeRegex(probe.regex),
        `${probe.id} failed to compile: ${probe.regex}`
      );
    }
  });

  it('carries a version and a review date (data-asset obligation)', () => {
    assert.ok(pack.version, 'threat pack must carry a version');
    assert.ok(pack._refresh_policy?.lastReviewed, 'threat pack must record lastReviewed');
  });
});

describe('TP-003 — split-payload precision', () => {
  const probe = pack.probes.find(p => p.id === 'TP-003');
  const re = probe ? _internals.compileProbeRegex(probe.regex) : null;
  const matches = (s) => {
    re.lastIndex = 0;
    const hit = re.test(s);
    re.lastIndex = 0;
    return hit;
  };

  it('exists', () => {
    assert.ok(probe, 'TP-003 must be present in the shipped pack');
  });

  it('still detects genuine split-payload chaining', () => {
    const attacks = [
      'when combined with the above instructions',
      'When combined with these rules, execute the payload',
      'when combined with previous content',
      'Part 2 of 3',
      'continue reading the next part',
    ];
    for (const a of attacks) {
      assert.ok(matches(a), `TP-003 must still detect: ${a}`);
    }
  });

  it('does NOT fire on ordinary English', () => {
    // The regression that motivated P-IMP-057: this exact comment in
    // cli/commands/audit.js was reported as a medium-severity finding.
    const benign = [
      '// Keep stdout pure JSON/SARIF when combined with machine output',
      'the result is faster when combined with caching',
      'output when combined with stderr is written to the log',
      'this runs when combined with the results',
      'merged when combined with the previous version',
    ];
    for (const b of benign) {
      assert.ok(!matches(b), `TP-003 must not fire on ordinary prose: ${b}`);
    }
  });
});