/**
 * Smoke tests for ModelFileScanner.
 *
 * Builds a synthetic model file inside a tmp dir and asserts the scanner
 * flags the right risk class.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { ModelFileScanner } from '../agents/model-file-scanner.js';

function mkTmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-modelfix-'));
}

function writeFakePickle(filePath, opts = {}) {
  // Synthesize a minimal pickle stream containing GLOBAL + REDUCE opcodes
  // that reference posix.system. Not intended to be executable — just to
  // match the static signature the scanner looks for.
  const parts = [];
  parts.push(Buffer.from([0x80, 0x04]));
  parts.push(Buffer.from('cposix\nsystem\n', 'binary'));
  parts.push(Buffer.from([0x52]));
  if (opts.benign) {
    parts.push(Buffer.from('benign-tensor-bytes-no-dangerous-symbols', 'binary'));
  }
  parts.push(Buffer.from([0x2E]));
  fs.writeFileSync(filePath, Buffer.concat(parts));
}

function writeFakeSafeTensors(filePath) {
  // SafeTensors header: 8-byte little-endian length + JSON header + data.
  const header = Buffer.from(JSON.stringify({ __metadata__: { format: 'pt' } }));
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(header.length), 0);
  fs.writeFileSync(filePath, Buffer.concat([len, header, Buffer.from('weights')]));
}

test('flags pickle-format models with high severity', async () => {
  const dir = mkTmp();
  const file = path.join(dir, 'model.pt');
  writeFakePickle(file);
  fs.writeFileSync(path.join(dir, 'README.md'), '# model card\n');

  const scanner = new ModelFileScanner();
  const findings = await scanner.analyze({ rootPath: dir });
  const formatF = findings.find(f => f.rule === 'MODEL_FILE_PICKLE_FORMAT');
  assert.ok(formatF, 'expected MODEL_FILE_PICKLE_FORMAT finding');
  assert.equal(formatF.severity, 'high');
  assert.equal(formatF.cwe, 'CWE-502');
});

test('flags pickle artifact that imports a dangerous module as critical', async () => {
  const dir = mkTmp();
  const file = path.join(dir, 'evil.pkl');
  writeFakePickle(file);
  fs.writeFileSync(path.join(dir, 'MODEL_CARD.md'), '# card\n');

  const scanner = new ModelFileScanner();
  const findings = await scanner.analyze({ rootPath: dir });
  const danger = findings.find(f => f.rule === 'MODEL_FILE_PICKLE_DANGEROUS_IMPORT');
  assert.ok(danger, 'expected MODEL_FILE_PICKLE_DANGEROUS_IMPORT finding');
  assert.equal(danger.severity, 'critical');
});

test('safetensors only emits low-severity informational finding', async () => {
  const dir = mkTmp();
  fs.writeFileSync(path.join(dir, 'README.md'), 'card');
  writeFakeSafeTensors(path.join(dir, 'weights.safetensors'));

  const scanner = new ModelFileScanner();
  const findings = await scanner.analyze({ rootPath: dir });
  const f = findings.find(x => x.rule === 'MODEL_FILE_SAFETENSORS');
  assert.ok(f);
  assert.equal(f.severity, 'low');
  assert.ok(!findings.some(x => x.rule === 'MODEL_FILE_PICKLE_FORMAT'));
});

test('flags missing model card alongside model artifact', async () => {
  const dir = mkTmp();
  writeFakeSafeTensors(path.join(dir, 'weights.safetensors'));

  const scanner = new ModelFileScanner();
  const findings = await scanner.analyze({ rootPath: dir });
  const card = findings.find(f => f.rule === 'MODEL_FILE_NO_CARD');
  assert.ok(card, 'expected MODEL_FILE_NO_CARD finding');
  assert.equal(card.severity, 'low');
});

test('returns empty when no model files are present', async () => {
  const dir = mkTmp();
  fs.writeFileSync(path.join(dir, 'app.py'), 'print("hello")\n');

  const scanner = new ModelFileScanner();
  const findings = await scanner.analyze({ rootPath: dir });
  assert.deepEqual(findings, []);
});

test('shouldRun returns true when models or Python detected, false otherwise', () => {
  const scanner = new ModelFileScanner();
  
  // Model files present
  assert.equal(scanner.shouldRun({ hasModelFiles: true }), true);
  
  // Python detected
  assert.equal(scanner.shouldRun({ languages: new Set(['python']) }), true);
  assert.equal(scanner.shouldRun({ languages: ['python'] }), true);
  
  // Neither detected
  assert.equal(scanner.shouldRun({ hasModelFiles: false, languages: ['javascript', 'go'] }), false);
});
