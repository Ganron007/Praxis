/**
 * Guard Command
 * =============
 *
 * Installs a git pre-push hook that runs praxis scan before every push.
 * If secrets are found, the push is blocked.
 *
 * USAGE:
 *   praxis guard                    Install pre-push hook
 *   praxis guard --pre-commit       Install pre-commit hook instead
 *   praxis guard remove             Remove installed hooks
 *
 * HUSKY SUPPORT:
 *   If a .husky/ directory is detected, the hook is added there instead.
 *   Otherwise it goes directly into .git/hooks/.
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import * as output from '../utils/output.js';

// =============================================================================
// HOOK SCRIPTS
// =============================================================================

const PRE_PUSH_HOOK = `#!/bin/sh
# praxis pre-push hook
# Scans for leaked secrets before every git push.
# Remove this hook with: npx praxis guard remove

echo ""
echo "🔍 praxis: Scanning for secrets before push..."

npx --yes praxis scan . --json > /tmp/praxis-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ praxis: Secrets detected! Push blocked."
  echo ""
  echo "Run 'npx praxis scan .' to see details."
  echo "Fix the issues, then push again."
  echo ""
  echo "To skip this check (not recommended):"
  echo "  git push --no-verify"
  echo ""
  rm -f /tmp/praxis-scan.json
  exit 1
fi

echo "✅ praxis: No secrets detected. Pushing..."
rm -f /tmp/praxis-scan.json
exit 0
`;

const PRE_COMMIT_HOOK = `#!/bin/sh
# praxis pre-commit hook
# Scans staged files for leaked secrets before every commit.
# Remove this hook with: npx praxis guard remove

echo ""
echo "🔍 praxis: Scanning for secrets before commit..."

npx --yes praxis scan . --json > /tmp/praxis-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ praxis: Secrets detected! Commit blocked."
  echo ""
  echo "Run 'npx praxis scan .' to see details."
  echo "Fix the issues, then commit again."
  echo ""
  echo "To skip this check (not recommended):"
  echo "  git commit --no-verify"
  echo ""
  rm -f /tmp/praxis-scan.json
  exit 1
fi

echo "✅ praxis: No secrets detected. Committing..."
rm -f /tmp/praxis-scan.json
exit 0
`;

const HUSKY_PRE_PUSH = `#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

echo ""
echo "🔍 praxis: Scanning for secrets before push..."

npx praxis scan . --json > /tmp/praxis-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ praxis: Secrets detected! Push blocked."
  echo "Run 'npx praxis scan .' to see details."
  rm -f /tmp/praxis-scan.json
  exit 1
fi

echo "✅ praxis: No secrets detected."
rm -f /tmp/praxis-scan.json
`;

const HUSKY_PRE_COMMIT = `#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

echo ""
echo "🔍 praxis: Scanning for secrets before commit..."

npx praxis scan . --json > /tmp/praxis-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ praxis: Secrets detected! Commit blocked."
  echo "Run 'npx praxis scan .' to see details."
  rm -f /tmp/praxis-scan.json
  exit 1
fi

echo "✅ praxis: No secrets detected."
rm -f /tmp/praxis-scan.json
`;

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function guardCommand(action, options = {}) {
  const cwd = process.cwd();

  // Verify this is a git repo
  const gitDir = findGitDir(cwd);
  if (!gitDir) {
    output.error('Not a git repository. Run this from your project root.');
    process.exit(1);
  }

  if (options.generateHooks) {
    return generateClaudeHooks(cwd);
  }

  if (action === 'remove') {
    return removeHooks(gitDir, cwd);
  }

  return installHook(gitDir, cwd, options);
}

// =============================================================================
// INSTALL
// =============================================================================

function installHook(gitDir, cwd, options) {
  const hookType = options.preCommit ? 'pre-commit' : 'pre-push';
  const hookScript = options.preCommit ? PRE_COMMIT_HOOK : PRE_PUSH_HOOK;
  const huskyScript = options.preCommit ? HUSKY_PRE_COMMIT : HUSKY_PRE_PUSH;

  output.header('Installing praxis Guard');

  // Check for Husky
  const huskyDir = path.join(cwd, '.husky');
  const useHusky = fs.existsSync(huskyDir);

  if (useHusky) {
    installHuskyHook(huskyDir, hookType, huskyScript);
  } else {
    installGitHook(gitDir, hookType, hookScript);
  }

  console.log();
  console.log(chalk.gray('What happens now:'));
  console.log(chalk.gray(`  Every git ${hookType === 'pre-push' ? 'push' : 'commit'} will run praxis scan`));
  console.log(chalk.gray('  If secrets are found, the operation is blocked'));
  console.log(chalk.gray('  Use --no-verify to skip (not recommended)'));
  console.log();
  console.log(chalk.gray('To remove: npx praxis guard remove'));
}

function installGitHook(gitDir, hookType, script) {
  const hooksDir = path.join(gitDir, 'hooks');
  const hookPath = path.join(hooksDir, hookType);

  // Ensure hooks directory exists
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  // Check if hook already exists (not from praxis)
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');
    if (!existing.includes('praxis')) {
      output.warning(`Existing ${hookType} hook found. Appending praxis check.`);
      fs.appendFileSync(hookPath, '\n' + script);
      output.success(`Appended to .git/hooks/${hookType}`);
      return;
    }
    output.warning(`praxis guard already installed in .git/hooks/${hookType}`);
    return;
  }

  fs.writeFileSync(hookPath, script);
  // Make executable (chmod +x)
  try {
    fs.chmodSync(hookPath, '755');
  } catch {
    // Windows doesn't support chmod, but hooks still run via git
  }

  output.success(`Hook installed at .git/hooks/${hookType}`);
}

function installHuskyHook(huskyDir, hookType, script) {
  const hookPath = path.join(huskyDir, hookType);

  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');
    if (!existing.includes('praxis')) {
      output.warning(`Existing Husky ${hookType} found. Appending praxis check.`);
      fs.appendFileSync(hookPath, '\n# praxis\n' + script.split('\n').slice(3).join('\n'));
      output.success(`Appended to .husky/${hookType}`);
      return;
    }
    output.warning(`praxis guard already installed in .husky/${hookType}`);
    return;
  }

  fs.writeFileSync(hookPath, script);
  try {
    fs.chmodSync(hookPath, '755');
  } catch {}

  output.success(`Hook installed at .husky/${hookType} (Husky detected)`);
}

// =============================================================================
// REMOVE
// =============================================================================

function removeHooks(gitDir, cwd) {
  output.header('Removing praxis Guard');

  let removed = 0;

  // Check .git/hooks
  const hookTypes = ['pre-push', 'pre-commit'];
  for (const hookType of hookTypes) {
    const hookPath = path.join(gitDir, 'hooks', hookType);
    if (fs.existsSync(hookPath)) {
      const content = fs.readFileSync(hookPath, 'utf-8');
      if (content.includes('praxis')) {
        if (content.trim() === PRE_PUSH_HOOK.trim() || content.trim() === PRE_COMMIT_HOOK.trim()) {
          // Praxis is the only hook — delete the file
          fs.unlinkSync(hookPath);
          output.success(`Removed .git/hooks/${hookType}`);
        } else {
          // Other hooks exist — only remove praxis lines
          const cleaned = content
            .replace(/# praxis[\s\S]*?exit 0\n/g, '')
            .trimEnd() + '\n';
          fs.writeFileSync(hookPath, cleaned);
          output.success(`Removed praxis from .git/hooks/${hookType}`);
        }
        removed++;
      }
    }

    // Check .husky
    const huskyHookPath = path.join(cwd, '.husky', hookType);
    if (fs.existsSync(huskyHookPath)) {
      const content = fs.readFileSync(huskyHookPath, 'utf-8');
      if (content.includes('praxis')) {
        fs.unlinkSync(huskyHookPath);
        output.success(`Removed .husky/${hookType}`);
        removed++;
      }
    }
  }

  if (removed === 0) {
    output.warning('No praxis hooks found.');
  }
}

// =============================================================================
// CLAUDE CODE DEFENSIVE HOOKS
// =============================================================================

function generateClaudeHooks(cwd) {
  output.header('Generating Defensive Claude Code Hooks');

  const claudeDir = path.join(cwd, '.claude');
  const settingsPath = path.join(claudeDir, 'settings.json');

  // Defensive hooks that block common attack patterns
  const preToolCmd = [
    'node -e "',
    'const c=process.argv[1]||String();',
    'const bad=[/curl.*[|].*(?:bash|sh|node|python)/i,/wget.*[|].*(?:bash|sh)/i,',
    '/rm\\s+-rf\\s+\\//,/webhook[.]site|requestbin|ngrok[.]io|pipedream/i,',
    '/base64.*-d.*[|].*(?:bash|sh)/i];',
    'const m=bad.find(r=>r.test(c));',
    'if(m){console.error(String.fromCharCode(10060)+String.fromCharCode(32)+c.slice(0,80));process.exit(1)}',
    '" "$INPUT"',
  ].join('');

  const postToolCmd = [
    'node -e "',
    'const f=process.argv[1]||String();',
    'if(/[.]env$|[.]env[.]/.test(f)){console.log(String.fromCharCode(9888)+String.fromCharCode(32)+f)}',
    '" "$INPUT"',
  ].join('');

  const defensiveHooks = {
    hooks: {
      PreToolUse: [
        {
          matcher: 'Bash',
          command: preToolCmd,
          description: 'Praxis: Block dangerous command patterns (curl|bash, rm -rf /, exfil domains)',
        },
      ],
      PostToolUse: [
        {
          matcher: 'Write',
          command: postToolCmd,
          description: 'Praxis: Alert when .env files are modified',
        },
      ],
    },
  };

  // Merge with existing settings
  let existing = {};
  if (fs.existsSync(settingsPath)) {
    try {
      existing = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    } catch { /* fresh start */ }
  }

  // Merge hooks — don't overwrite existing hooks, append
  if (!existing.hooks) existing.hooks = {};
  if (!existing.hooks.PreToolUse) existing.hooks.PreToolUse = [];
  if (!existing.hooks.PostToolUse) existing.hooks.PostToolUse = [];

  // Check if praxis hooks already present
  const hasPreHook = existing.hooks.PreToolUse.some(h => h.description?.includes('Praxis'));
  const hasPostHook = existing.hooks.PostToolUse.some(h => h.description?.includes('Praxis'));

  if (hasPreHook && hasPostHook) {
    output.warning('Praxis hooks already installed in .claude/settings.json');
    return;
  }

  if (!hasPreHook) {
    existing.hooks.PreToolUse.push(...defensiveHooks.hooks.PreToolUse);
  }
  if (!hasPostHook) {
    existing.hooks.PostToolUse.push(...defensiveHooks.hooks.PostToolUse);
  }

  // Write
  if (!fs.existsSync(claudeDir)) fs.mkdirSync(claudeDir, { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(existing, null, 2) + '\n');

  output.success('Defensive hooks installed in .claude/settings.json');
  console.log();
  console.log(chalk.gray('  Hooks installed:'));
  console.log(chalk.gray('    PreToolUse  → Block curl|bash, rm -rf /, exfil domains'));
  console.log(chalk.gray('    PostToolUse → Alert on .env file modifications'));
  console.log();
  console.log(chalk.gray('  These hooks protect against:'));
  console.log(chalk.gray('    • Remote code execution via piped downloads'));
  console.log(chalk.gray('    • Data exfiltration to webhook.site/ngrok/requestbin'));
  console.log(chalk.gray('    • Destructive filesystem operations'));
  console.log(chalk.gray('    • Unauthorized .env modifications'));
  console.log();
}

// =============================================================================
// UTILITIES
// =============================================================================

function findGitDir(startPath) {
  let current = startPath;

  while (true) {
    const gitPath = path.join(current, '.git');
    if (fs.existsSync(gitPath)) {
      return gitPath;
    }
    const parent = path.dirname(current);
    if (parent === current) return null; // Reached filesystem root
    current = parent;
  }
}
