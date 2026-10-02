/**
 * Tests for cli/core/ — the new shared utilities introduced in the
 * praxis rebrand. Covers:
 *   - cli/core/fs.js          (validatePath, validateDir, ensureDir)
 *   - cli/core/errors.js      (safeCatch, safeCatchAsync, toError)
 *   - cli/core/output/index.js (formatter registry: render, listFormats, registerFormat)
 *   - cli/core/output/json.js
 *   - cli/core/output/sarif.js
 *   - cli/core/branding.js    (PRODUCT_NAME constant + banner doesn't throw)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

// =============================================================================
// fs.js
// =============================================================================

describe('cli/core/fs', async () => {
  const { validatePath, validateDir, ensureDir } = await import('../core/fs.js');

  it('validatePath returns absolute path for existing dir', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-fs-test-'));
    try {
      const resolved = validatePath(tmp);
      assert.equal(resolved, path.resolve(tmp));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('validatePath returns null for missing path when exitOnMissing=false', () => {
    const missing = path.join(os.tmpdir(), 'praxis-does-not-exist-' + Date.now());
    const result = validatePath(missing, { exitOnMissing: false });
    assert.equal(result, null);
  });

  it('validateDir rejects a regular file when exitOnMissing=false', () => {
    const tmpFile = path.join(os.tmpdir(), 'praxis-fs-file-' + Date.now() + '.txt');
    fs.writeFileSync(tmpFile, 'hi');
    try {
      const result = validateDir(tmpFile, { exitOnMissing: false });
      assert.equal(result, null);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  it('ensureDir creates a missing directory and is idempotent', () => {
    const tmp = path.join(os.tmpdir(), 'praxis-ensure-' + Date.now(), 'a', 'b');
    try {
      ensureDir(tmp);
      assert.ok(fs.existsSync(tmp));
      // Idempotent — second call must not throw.
      ensureDir(tmp);
      assert.ok(fs.existsSync(tmp));
    } finally {
      fs.rmSync(path.dirname(path.dirname(tmp)), { recursive: true, force: true });
    }
  });
});

// =============================================================================
// errors.js
// =============================================================================

describe('cli/core/errors', async () => {
  const { safeCatch, safeCatchAsync, toError } = await import('../core/errors.js');

  it('safeCatch returns the function value on success', () => {
    assert.equal(safeCatch(() => 42, 0), 42);
  });

  it('safeCatch returns fallback on throw', () => {
    const result = safeCatch(() => { throw new Error('boom'); }, 'fallback');
    assert.equal(result, 'fallback');
  });

  it('safeCatchAsync awaits and returns value', async () => {
    const result = await safeCatchAsync(async () => 'ok', 'fail');
    assert.equal(result, 'ok');
  });

  it('safeCatchAsync returns fallback on async throw', async () => {
    const result = await safeCatchAsync(async () => { throw new Error('nope'); }, 'fail');
    assert.equal(result, 'fail');
  });

  it('toError wraps non-Error values', () => {
    assert.ok(toError('a string') instanceof Error);
    assert.ok(toError({ code: 1 }) instanceof Error);
    assert.ok(toError(new Error('already')) instanceof Error);
    assert.equal(toError('msg').message, 'msg');
  });
});

// =============================================================================
// output/index.js — formatter registry
// =============================================================================

describe('cli/core/output registry', async () => {
  const { render, listFormats, hasFormat, registerFormat } = await import('../core/output/index.js');

  it('lists the built-in formats', () => {
    const formats = listFormats();
    assert.ok(formats.includes('json'));
    assert.ok(formats.includes('sarif'));
  });

  it('hasFormat returns true for known and false for unknown', () => {
    assert.equal(hasFormat('json'), true);
    assert.equal(hasFormat('does-not-exist'), false);
  });

  it('render() throws for unknown format with helpful message', () => {
    assert.throws(
      () => render('xml', {}),
      /unknown format 'xml'.*available:/
    );
  });

  it('registerFormat extends the registry', () => {
    registerFormat('plain', (report) => `findings=${(report.findings || []).length}`);
    assert.equal(render('plain', { findings: [1, 2, 3] }), 'findings=3');
  });
});

// =============================================================================
// output/json.js
// =============================================================================

describe('cli/core/output/json', async () => {
  const { render } = await import('../core/output/index.js');

  it('emits schemaVersion and pretty-prints by default', () => {
    const out = render('json', { findings: [{ severity: 'high' }] });
    const parsed = JSON.parse(out);
    assert.equal(parsed.schemaVersion, 3);
    assert.equal(parsed.findings.length, 1);
    // Pretty-print check — newlines present.
    assert.ok(out.includes('\n'));
  });

  it('compact mode strips whitespace', () => {
    const out = render('json', { findings: [] }, { pretty: false });
    assert.ok(!out.includes('\n'));
  });
});

// =============================================================================
// output/sarif.js
// =============================================================================

describe('cli/core/output/sarif', async () => {
  const { render } = await import('../core/output/index.js');

  it('produces a valid SARIF v2.1.0 envelope', () => {
    const out = render('sarif', {
      findings: [
        {
          ruleId: 'aws-key',
          patternName: 'AWS Access Key',
          severity: 'critical',
          file: 'src/leaked.js',
          line: 12,
          description: 'Hardcoded AWS access key',
        },
      ],
    });
    const parsed = JSON.parse(out);
    assert.equal(parsed.version, '2.1.0');
    assert.equal(parsed.runs.length, 1);
    assert.equal(parsed.runs[0].tool.driver.name, 'praxis');
    assert.equal(parsed.runs[0].results.length, 1);
    assert.equal(parsed.runs[0].results[0].level, 'error'); // critical → error
    assert.equal(parsed.runs[0].results[0].locations[0].physicalLocation.region.startLine, 12);
  });

  it('deduplicates rules across multiple findings sharing a ruleId', () => {
    const out = render('sarif', {
      findings: [
        { ruleId: 'r1', severity: 'high', file: 'a.js', line: 1 },
        { ruleId: 'r1', severity: 'high', file: 'b.js', line: 2 },
        { ruleId: 'r2', severity: 'low', file: 'c.js', line: 3 },
      ],
    });
    const parsed = JSON.parse(out);
    assert.equal(parsed.runs[0].tool.driver.rules.length, 2);
  });

  // ── GitHub `security-severity` (P-IMP-058) ─────────────────────────────────
  // `level` alone collapsed critical and high into the same bucket, so every Code
  // Scanning consumer saw compressed severity. `security-severity` is the numeric
  // property GitHub ranks and filters on.
  describe('security-severity', () => {
    const rulesOf = (findings) => JSON.parse(render('sarif', { findings })).runs[0].tool.driver.rules;
    const resultsOf = (findings) => JSON.parse(render('sarif', { findings })).runs[0].results;
    const sevOf = (rules, id) => Number(rules.find(r => r.id === id)?.properties['security-severity']);

    const TIERS = [
      ['critical', 'R_CRIT'],
      ['high', 'R_HIGH'],
      ['medium', 'R_MED'],
      ['low', 'R_LOW'],
    ];

    it('emits a numeric security-severity on every rule and result', () => {
      const findings = TIERS.map(([severity, ruleId]) => ({ ruleId, severity, file: 'a.js', line: 1 }));
      for (const r of rulesOf(findings)) {
        assert.ok(r.properties['security-severity'] !== undefined, `${r.id} has no security-severity`);
        assert.ok(Number.isFinite(Number(r.properties['security-severity'])), `${r.id} is not numeric`);
      }
      for (const r of resultsOf(findings)) {
        assert.ok(r.properties['security-severity'] !== undefined, `${r.ruleId} result has no security-severity`);
      }
    });

    it('orders severities so GitHub can rank them', () => {
      const findings = TIERS.map(([severity, ruleId]) => ({ ruleId, severity, file: 'a.js', line: 1 }));
      const rules = rulesOf(findings);
      const crit = sevOf(rules, 'R_CRIT');
      const high = sevOf(rules, 'R_HIGH');
      const med = sevOf(rules, 'R_MED');
      const low = sevOf(rules, 'R_LOW');
      assert.ok(crit > high, 'critical must outrank high');
      assert.ok(high > med, 'high must outrank medium');
      assert.ok(med > low, 'medium must outrank low');
      assert.ok(low >= 0 && crit <= 10, 'values must sit in the 0.0-10.0 range GitHub expects');
    });

    it('separates critical from high even though they share a SARIF level', () => {
      // The whole point of the fix: same coarse gate, different rank.
      const rules = rulesOf([
        { ruleId: 'R_CRIT', severity: 'critical', file: 'a.js', line: 1 },
        { ruleId: 'R_HIGH', severity: 'high', file: 'a.js', line: 1 },
      ]);
      const crit = rules.find(r => r.id === 'R_CRIT');
      const high = rules.find(r => r.id === 'R_HIGH');
      assert.equal(crit.defaultConfiguration.level, high.defaultConfiguration.level);
      assert.notEqual(crit.properties['security-severity'], high.properties['security-severity']);
    });

    it('does not let a missing or unknown severity read as low-risk', () => {
      const rules = rulesOf([
        { ruleId: 'R_MISSING', file: 'a.js', line: 1 },
        { ruleId: 'R_UNKNOWN', severity: 'catastrophic', file: 'a.js', line: 1 },
      ]);
      for (const r of rules) {
        assert.ok(Number(r.properties['security-severity']) >= 5, `${r.id} defaulted too low`);
        assert.equal(r.defaultConfiguration.level, 'warning');
      }
    });

    it('keeps a result level consistent with its rule definition', () => {
      const findings = TIERS.map(([severity, ruleId]) => ({ ruleId, severity, file: 'a.js', line: 1 }));
      const rules = rulesOf(findings);
      for (const result of resultsOf(findings)) {
        const rule = rules.find(r => r.id === result.ruleId);
        assert.equal(result.level, rule.defaultConfiguration.level, `${result.ruleId} level drifted`);
        assert.equal(
          result.properties['security-severity'],
          rule.properties['security-severity'],
          `${result.ruleId} severity drifted`
        );
      }
    });

    it('preserves the pre-existing properties', () => {
      const results = resultsOf([
        { ruleId: 'R1', severity: 'high', file: 'a.js', line: 1, cwe: 'CWE-918', owasp: 'A10:2021' },
      ]);
      assert.equal(results[0].properties.cwe, 'CWE-918');
      assert.equal(results[0].properties.owasp, 'A10:2021');
    });
  });
});

// =============================================================================
// P-IMP-062 / P-IMP-063 — one SARIF serializer, reachable from every command
// =============================================================================
//
// Four commands carried private SARIF serializers. The `security-severity` fix
// landed in the registry and reached almost nobody — including the GitHub Action's
// `scan ci --sarif` call, which emitted 0 of 12 rules with a severity. These tests
// pin both the behaviour and the structure that let it happen.

describe('sarif consolidation', async () => {
  const { renderFindingsSARIF } = await import('../core/output/sarif.js');
  const COMMANDS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'commands');

  const parse = (json) => JSON.parse(json);
  const uriOf = (doc, i = 0) =>
    doc.runs[0].results[i].locations[0].physicalLocation.artifactLocation.uri;

  it('no command may define a private SARIF serializer', () => {
    // Structural guard for the actual root cause: a duplicated `runs: [{ ... }]`
    // literal with a `tool.driver` is how the drift started.
    const dir = COMMANDS_DIR;
    const offenders = [];
    for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(dir, file), 'utf8');
      if (/runs:\s*\[\s*\{/.test(src) && /tool:\s*\{/.test(src) && /driver:\s*\{/.test(src)) {
        offenders.push(file);
      }
    }
    assert.deepEqual(offenders, [],
      `these commands build SARIF by hand — use core/output/sarif.js: ${offenders.join(', ')}`);
  });

  it('no command may hardcode a SARIF driver version', () => {
    const dir = COMMANDS_DIR;
    const offenders = [];
    for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(dir, file), 'utf8');
      const m = src.match(/driver:\s*\{[^}]*version:\s*'([^']+)'/);
      if (m) offenders.push(`${file} -> ${m[1]}`);
    }
    assert.deepEqual(offenders, [], `hardcoded driver versions: ${offenders.join(', ')}`);
  });

  it('renders the flat finding shape used by ci.js and audit.js', () => {
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R1', title: 'T', file: '/proj/src/a.js', line: 3, severity: 'critical', description: 'd' }],
      { rootPath: '/proj' },
    ));
    assert.equal(out.runs[0].results[0].ruleId, 'R1');
    assert.equal(out.runs[0].tool.driver.rules[0].properties['security-severity'], '9.5');
    assert.equal(uriOf(out) , 'src/a.js');
  });

  it('renders the nested orchestrator shape used by scan.js', () => {
    const out = parse(renderFindingsSARIF(
      [{ file: '/proj/src/b.js', findings: [{ patternName: 'Nested', severity: 'low', description: 'n', line: 9 }] }],
      { rootPath: '/proj' },
    ));
    assert.equal(out.runs[0].results[0].ruleId, 'Nested');
    assert.equal(out.runs[0].tool.driver.rules[0].properties['security-severity'], '2.5');
    assert.equal(uriOf(out), 'src/b.js');
  });

  it('relativizes artifact URIs against rootPath so no local path leaks', () => {
    // Built with path.join so the fixture uses the host separator: on POSIX a
    // backslash-style path is just a filename, and path.relative cannot relativize it.
    const root = path.join('C:', 'Users', 'alice', 'projects', 'myapp');
    const file = path.join(root, 'src', 'db.js');
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R', file, severity: 'high' }],
      { rootPath: root },
    ));
    const uri = out.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri, 'src/db.js');
    assert.ok(!uri.includes('alice'), 'must not leak the local username');
    assert.ok(!uri.startsWith('/') && !/^[A-Za-z]:/.test(uri), 'must be repo-relative');
  });

  it('never emits an escaping or absolute URI', () => {
    // A finding outside the root must still not become an absolute path.
    const root = path.join('C:', 'proj');
    const outside = path.join('C:', 'elsewhere', 'secret.js');
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R', file: outside, severity: 'high' }],
      { rootPath: root },
    ));
    const uri = out.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.ok(!uri.includes('..'), `must not escape the root: ${uri}`);
    assert.ok(!/^[A-Za-z]:/.test(uri) && !uri.startsWith('/'), `must not be absolute: ${uri}`);
  });

  it('leaves an already-relative path intact when rootPath is supplied', () => {
    // Regression: `path.relative(root, 'src/nested/deep.js')` resolves the input against
    // the cwd, escapes the root, and the outside-root fallback then reduced it to
    // `deep.js` — an alert Code Scanning cannot locate.
    const root = path.join('C:', 'proj');
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R', file: path.join('src', 'nested', 'deep.js'), severity: 'high' }],
      { rootPath: root },
    ));
    assert.equal(uriOf(out), 'src/nested/deep.js');
  });

  it('does not hardcode a repository name when no rootPath is supplied', () => {
    // The old normalizer stripped a literal `/Praxis/`, written for this repo alone.
    const file = path.join('C:', 'a', 'Praxis', 'b.js');
    const out = parse(renderFindingsSARIF([{ rule: 'R', file, severity: 'high' }]));
    const uri = uriOf(out);
    assert.ok(uri.includes('Praxis'), `a user path containing "Praxis" must not be truncated: ${uri}`);
  });
});


// =============================================================================
// branding.js
// =============================================================================

describe('cli/core/branding', async () => {
  const branding = await import('../core/branding.js');

  it('exports product name and tagline', () => {
    assert.equal(branding.PRODUCT_NAME, 'praxis');
    assert.equal(typeof branding.TAGLINE, 'string');
    assert.ok(branding.TAGLINE.length > 0);
  });

  it('printBanner does not throw with or without a version', () => {
    // Capture stdout to keep test output clean, but still assert no throw.
    const origLog = console.log;
    console.log = () => {};
    try {
      assert.doesNotThrow(() => branding.printBanner());
      assert.doesNotThrow(() => branding.printBanner('1.0.0'));
    } finally {
      console.log = origLog;
    }
  });
});

// =============================================================================
// policy-engine.js
// =============================================================================

describe('cli/agents/policy-engine', async () => {
  const { PolicyEngine } = await import('../agents/policy-engine.js');

  it('enforces minimumScore and failOn severity', () => {
    const policy = new PolicyEngine({
      minimumScore: 70,
      failOn: 'high',
    });

    const scoreResult = { score: 65, grade: 'C' };
    const findings = [
      { severity: 'high', title: 'High risk finding', file: 'app.js', line: 10, rule: 'r1' },
      { severity: 'low', title: 'Low risk finding', file: 'app.js', line: 12, rule: 'r2' },
    ];

    const violations = policy.evaluate(scoreResult, findings);
    assert.equal(violations.length, 2);
    assert.equal(violations[0].type, 'minimum_score');
    assert.equal(violations[1].type, 'severity_threshold');
  });

  it('enforces requiredScans list', () => {
    const policy = new PolicyEngine({
      requiredScans: ['secrets', 'injection', 'deps'],
    });

    const scoreResult = { score: 90, grade: 'A' };
    
    // Test: missing 'injection' scan
    const violations = policy.evaluate(scoreResult, [], {
      agentResults: [{ agent: 'secrets-scanner', category: 'secrets', success: true }],
      depsRun: true,
      secretsRun: true,
    });
    
    assert.equal(violations.length, 1);
    assert.equal(violations[0].type, 'missing_scan');
    assert.ok(violations[0].message.includes('injection'));
  });

  it('enforces maxAge for dependency CVEs', () => {
    const policy = new PolicyEngine({
      maxAge: {
        criticalCVE: '7d',
        highCVE: '30d',
      },
    });

    const scoreResult = { score: 90, grade: 'A' };

    // Test: a critical CVE that is 10 days old (violates 7d SLA)
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const depVulns = [
      { name: 'old-package', severity: 'critical', cve: 'CVE-2026-1000', published: tenDaysAgo },
      { name: 'safe-package', severity: 'high', cve: 'CVE-2026-2000', published: new Date().toISOString() },
    ];

    const violations = policy.evaluate(scoreResult, [], { depVulns });
    assert.equal(violations.length, 1);
    assert.equal(violations[0].type, 'cve_sla_breach');
    assert.ok(violations[0].message.includes('old-package'));
  });
});

