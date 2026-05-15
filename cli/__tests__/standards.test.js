/**
 * Tests for the AI-security standards registry.
 *
 * Covers: registry shape, mapFinding semantics for each module,
 * aggregator summaries, and integration with ScoringEngine.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ALL_STANDARDS,
  listStandards,
  getStandard,
  mapFindingToStandards,
  getStandardsSummary,
  filterFindingsByStandard,
} from '../utils/standards/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';

test('ALL_STANDARDS contains expected modules', () => {
  const names = ALL_STANDARDS.map(s => s.name).sort();
  assert.deepEqual(names, [
    'avid',
    'eu-ai-act',
    'google-saif',
    'iso-42001',
    'mitre-atlas',
    'nist-ai-600-1',
    'owasp-llm',
    'owasp-ml',
  ]);
});

test('every standard exports required fields', () => {
  for (const s of ALL_STANDARDS) {
    assert.equal(typeof s.name, 'string', `${s.name}: name`);
    assert.equal(typeof s.version, 'string', `${s.name}: version`);
    assert.equal(typeof s.title, 'string', `${s.name}: title`);
    assert.equal(typeof s.description, 'string', `${s.name}: description`);
    assert.equal(typeof s.url, 'string', `${s.name}: url`);
    assert.ok(Array.isArray(s.controls) && s.controls.length > 0, `${s.name}: controls`);
    assert.equal(typeof s.mapFinding, 'function', `${s.name}: mapFinding`);
    for (const c of s.controls) {
      assert.equal(typeof c.id, 'string', `${s.name}: control.id`);
      assert.equal(typeof c.title, 'string', `${s.name}: control.title`);
    }
  }
});

test('listStandards returns metadata only (no mapFinding fn)', () => {
  const list = listStandards();
  assert.equal(list.length, ALL_STANDARDS.length);
  for (const item of list) {
    assert.ok(item.name);
    assert.ok(item.controlCount > 0);
    assert.equal(typeof item.mapFinding, 'undefined');
  }
});

test('getStandard returns module by name, null for unknown', () => {
  assert.equal(getStandard('owasp-llm').name, 'owasp-llm');
  assert.equal(getStandard('does-not-exist'), null);
});

test('mapFindingToStandards: prompt-injection finding hits LLM01 + ATLAS T0051', () => {
  const finding = {
    category: 'llm',
    rule: 'prompt-injection-direct',
    title: 'Direct prompt injection via user input',
    severity: 'high',
    cwe: null,
    owasp: 'ASI01',
  };
  const tagged = mapFindingToStandards(finding);
  assert.ok(tagged['owasp-llm'].includes('LLM01'));
  assert.ok(tagged['mitre-atlas'].includes('AML.T0051'));
  assert.ok(tagged['nist-ai-600-1'].includes('MP-5.1-GAI'));
});

test('mapFindingToStandards: secret in source maps to disclosure controls', () => {
  const finding = {
    category: 'secrets',
    rule: 'aws-access-key',
    title: 'AWS access key in source',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: null,
  };
  const tagged = mapFindingToStandards(finding);
  assert.ok(tagged['owasp-llm'].includes('LLM02'));
  assert.ok(tagged['mitre-atlas'].includes('AML.T0057'));
  assert.ok(tagged['avid'].includes('S0301'));
  assert.ok(tagged['iso-42001'].includes('A.6.2.6'));
});

test('mapFindingToStandards: supply-chain finding maps to LLM03 + ATLAS T0010', () => {
  const finding = {
    category: 'supply-chain',
    rule: 'compromised-package',
    title: 'Known-malicious npm package',
    severity: 'critical',
    cwe: null,
    owasp: 'ASI04',
  };
  const tagged = mapFindingToStandards(finding);
  assert.ok(tagged['owasp-llm'].includes('LLM03'));
  assert.ok(tagged['mitre-atlas'].includes('AML.T0010'));
  assert.ok(tagged['owasp-ml'].includes('ML06'));
});

test('mapFindingToStandards: unrelated finding produces empty tags', () => {
  const finding = {
    category: 'unknown',
    rule: 'no-match',
    title: 'Some random thing',
    severity: 'low',
    cwe: null,
    owasp: null,
  };
  const tagged = mapFindingToStandards(finding);
  assert.equal(typeof tagged, 'object');
  assert.ok(!('owasp-llm' in tagged) || tagged['owasp-llm'].length === 0);
});

test('getStandardsSummary aggregates findings by control', () => {
  const findings = [
    { category: 'llm', rule: 'prompt-injection', title: 'pi', severity: 'high', owasp: 'ASI01', cwe: null },
    { category: 'secrets', rule: 'token-leak', title: 'token leak', severity: 'critical', cwe: 'CWE-798', owasp: null },
    { category: 'supply-chain', rule: 'malicious-pkg', title: 'mal pkg', severity: 'high', owasp: 'ASI04', cwe: null },
  ];
  const summary = getStandardsSummary(findings);
  assert.ok(summary['owasp-llm']);
  assert.ok(summary['owasp-llm'].flaggedControls > 0);
  assert.match(summary['owasp-llm'].coverage, /^\d+\/\d+$/);
  const llm01 = summary['owasp-llm'].controls.find(c => c.id === 'LLM01');
  assert.equal(llm01.findingCount, 1);
  const llm02 = summary['owasp-llm'].controls.find(c => c.id === 'LLM02');
  assert.equal(llm02.findingCount, 1);
  const llm03 = summary['owasp-llm'].controls.find(c => c.id === 'LLM03');
  assert.equal(llm03.findingCount, 1);
});

test('filterFindingsByStandard filters to matching standard, optional control', () => {
  const findings = [
    { category: 'llm', rule: 'prompt-injection', title: 'pi', severity: 'high', owasp: 'ASI01', cwe: null },
    { category: 'secrets', rule: 'token-leak', title: 'token leak', severity: 'critical', cwe: 'CWE-798', owasp: null },
    { category: 'auth', rule: 'no-auth', title: 'missing auth', severity: 'high', cwe: 'CWE-306', owasp: null },
  ];
  const llmFindings = filterFindingsByStandard(findings, 'owasp-llm');
  assert.ok(llmFindings.length >= 2);

  const onlyLlm01 = filterFindingsByStandard(findings, 'owasp-llm', 'LLM01');
  assert.equal(onlyLlm01.length, 1);
  assert.equal(onlyLlm01[0].rule, 'prompt-injection');
});

test('ScoringEngine.compute attaches finding.standards and report.standardsSummary', () => {
  const findings = [
    { category: 'llm', rule: 'prompt-injection', title: 'pi', severity: 'high', confidence: 'high', owasp: 'ASI01', cwe: null },
    { category: 'secrets', rule: 'token', title: 'token', severity: 'critical', confidence: 'high', cwe: 'CWE-798', owasp: null },
  ];
  const result = new ScoringEngine().compute(findings, []);
  assert.ok(result.standardsSummary);
  assert.ok(result.standardsSummary['owasp-llm']);
  for (const f of findings) {
    assert.equal(typeof f.standards, 'object');
  }
  const piTags = findings[0].standards['owasp-llm'] || [];
  assert.ok(piTags.includes('LLM01'));
});
