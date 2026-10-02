/**
 * Tests for cli/core/git-clone.js — remote Git repository scanning.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { isGitUrl, parseGitUrl, redactGitUrl, checkGitInstalled, cloneGitRepo } from '../core/git-clone.js';

describe('cli/core/git-clone', () => {
  describe('isGitUrl', () => {
    it('recognises HTTPS GitHub URLs', () => {
      assert.equal(isGitUrl('https://github.com/OWASP/wrongsecrets'), true);
      assert.equal(isGitUrl('https://github.com/OWASP/wrongsecrets.git'), true);
    });

    it('recognises SSH Git URLs', () => {
      assert.equal(isGitUrl('git@github.com:OWASP/wrongsecrets.git'), true);
      assert.equal(isGitUrl('git@gitlab.com:group/project.git'), true);
    });

    it('recognises git:// and ssh:// protocols', () => {
      assert.equal(isGitUrl('git://github.com/OWASP/wrongsecrets.git'), true);
      assert.equal(isGitUrl('ssh://git@github.com/OWASP/wrongsecrets.git'), true);
    });

    it('recognises shorthand aliases', () => {
      assert.equal(isGitUrl('gh:OWASP/wrongsecrets'), true);
      assert.equal(isGitUrl('github:OWASP/wrongsecrets'), true);
      assert.equal(isGitUrl('gitlab:group/project'), true);
      assert.equal(isGitUrl('github.com/OWASP/wrongsecrets'), true);
    });

    it('rejects local file and directory paths', () => {
      assert.equal(isGitUrl('.'), false);
      assert.equal(isGitUrl('./src'), false);
      assert.equal(isGitUrl('package.json'), false);
      assert.equal(isGitUrl('C:\\some\\path'), false);
      assert.equal(isGitUrl('/tmp/local/dir'), false);
    });

    it('rejects non-strings and empty input', () => {
      assert.equal(isGitUrl(''), false);
      assert.equal(isGitUrl(null), false);
      assert.equal(isGitUrl(undefined), false);
    });
  });

  describe('redactGitUrl', () => {
    it('redacts tokens and passwords from https URLs', () => {
      const url = 'https://x-access-token:ghp_secretToken12345@github.com/owner/repo.git';
      const redacted = redactGitUrl(url);
      assert.equal(redacted, 'https://***@github.com/owner/repo.git');
      assert.ok(!redacted.includes('ghp_secretToken12345'));
    });

    it('leaves public URLs unchanged', () => {
      const url = 'https://github.com/owner/repo.git';
      assert.equal(redactGitUrl(url), url);
    });
  });

  describe('parseGitUrl', () => {
    it('parses repoName and provider for github https URLs', () => {
      const parsed = parseGitUrl('https://github.com/OWASP/wrongsecrets.git');
      assert.equal(parsed.repoName, 'wrongsecrets');
      assert.equal(parsed.provider, 'github');
      assert.equal(parsed.displayUrl, 'https://github.com/OWASP/wrongsecrets.git');
    });

    it('expands shorthand gh: prefix', () => {
      const parsed = parseGitUrl('gh:org/my-project');
      assert.equal(parsed.repoName, 'my-project');
      assert.equal(parsed.provider, 'github');
      assert.equal(parsed.displayUrl, 'https://github.com/org/my-project');
    });

    it('injects gitToken securely when provided', () => {
      const parsed = parseGitUrl('https://github.com/private-org/secret-repo.git', {
        gitToken: 'ghp_superSecretToken999',
      });
      assert.ok(parsed.cloneUrl.includes('ghp_superSecretToken999'));
      // Display URL must NEVER contain the secret
      assert.ok(!parsed.displayUrl.includes('ghp_superSecretToken999'));
    });
  });

  describe('checkGitInstalled', () => {
    it('returns a boolean without throwing', () => {
      const result = checkGitInstalled();
      assert.equal(typeof result, 'boolean');
    });
  });

  describe('cloneGitRepo with local test repo', () => {
    it('creates temporary workspace and cleans it up properly', () => {
      // Create a dummy local git repo in temp to test cloning
      const sourceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-test-src-'));
      fs.writeFileSync(path.join(sourceDir, 'README.md'), '# Test Repo\n');

      execFileSync('git', ['init'], { cwd: sourceDir, stdio: 'pipe' });
      execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: sourceDir, stdio: 'pipe' });
      execFileSync('git', ['config', 'user.name', 'Test User'], { cwd: sourceDir, stdio: 'pipe' });
      execFileSync('git', ['add', '.'], { cwd: sourceDir, stdio: 'pipe' });
      execFileSync('git', ['commit', '-m', 'Initial commit'], { cwd: sourceDir, stdio: 'pipe' });

      // Clone local repo path as git target
      const cloneResult = cloneGitRepo(sourceDir, { depth: 1 });
      assert.ok(fs.existsSync(cloneResult.tempDir));
      assert.ok(fs.existsSync(path.join(cloneResult.tempDir, 'README.md')));

      // Test cleanup
      cloneResult.cleanup();
      assert.equal(fs.existsSync(cloneResult.tempDir), false);

      // Clean up source
      fs.rmSync(sourceDir, { recursive: true, force: true });
    });
  });
});
