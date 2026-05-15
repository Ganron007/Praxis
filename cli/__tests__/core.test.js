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
