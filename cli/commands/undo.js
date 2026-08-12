/**
 * Undo Command
 * ============
 *
 * Reverts changes applied by `praxis fix interactive`.
 *
 * Reads .praxis/fixes.jsonl, takes the most recent entry (or all entries
 * with --all), and reverses each edit. Per-fix git commits made by the agent
 * are preferred over manual reversal when available.
 *
 * USAGE:
 *   praxis undo                Revert the last applied fix
 *   praxis undo --all          Revert every fix in the log
 *   praxis undo --dry-run      Show what would be reverted, but don't write
 */

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import chalk from 'chalk';
import * as output from '../utils/output.js';

const FIX_LOG_PATH = '.praxis/fixes.jsonl';

export async function undoCommand(targetPath = '.', options = {}) {
  const root    = path.resolve(targetPath);
  const logPath = path.join(root, FIX_LOG_PATH);

  if (!fs.existsSync(logPath)) {
    output.error(`No fix log found at ${FIX_LOG_PATH}`);
    console.log(chalk.gray('  Run `praxis fix interactive` first to apply fixes.'));
    process.exit(1);
  }

  const entries = fs.readFileSync(logPath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);

  if (entries.length === 0) {
    output.error('Fix log is empty.');
    process.exit(1);
  }

  const toUndo = options.all ? [...entries].reverse() : [entries[entries.length - 1]];

  console.log();
  output.header('Praxis — Undo');
  console.log();
  console.log(chalk.gray(`  Reverting ${toUndo.length} fix(es) from ${FIX_LOG_PATH}`));
  console.log();

  let reverted = 0;
  let failed   = 0;

  for (const entry of toUndo) {
    const file = entry.file || entry.finding?.file || '(unknown)';
    console.log(chalk.bold(`  ${chalk.cyan(file)}`));

    if (options.dryRun) {
      console.log(chalk.gray(`    Would reverse plan: ${entry.plan?.summary || 'no summary'}`));
      reverted++;
      continue;
    }

    try {
      reverseEntry(root, entry);
      console.log(chalk.green('    Reverted.'));
      reverted++;
    } catch (err) {
      console.log(chalk.red(`    Failed: ${err.message}`));
      failed++;
    }
  }

  // Truncate the log
  if (!options.dryRun && reverted > 0) {
    const remaining = options.all ? [] : entries.slice(0, -1);
    if (remaining.length === 0) {
      fs.unlinkSync(logPath);
    } else {
      fs.writeFileSync(logPath, remaining.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
    }
  }

  console.log();
  console.log(chalk.green(`  Reverted: ${reverted}`));
  if (failed > 0) console.log(chalk.red(`  Failed:   ${failed}`));
  console.log();

  if (failed > 0) {
    console.log(chalk.gray('  For failed entries, try `git checkout` or `git reset --hard` if you committed via --branch.'));
    console.log();
  }
}

function isGitRepo(dir) {
  try {
    execFileSync('git', ['-C', dir, 'rev-parse', '--is-inside-work-tree'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function reverseEntry(root, entry) {
  if (entry.commitHash && isGitRepo(root)) {
    try {
      execFileSync('git', ['-C', root, 'revert', '--no-commit', entry.commitHash], { stdio: 'ignore' });
      return;
    } catch {
      console.log(chalk.yellow(`    Git revert failed for ${entry.commitHash.slice(0, 7)}. Falling back to manual text reversal.`));
    }
  }

  const plan = entry.plan;
  if (!plan || !Array.isArray(plan.files) || plan.files.length === 0) {
    throw new Error('entry has no plan to reverse');
  }

  for (const fileChange of plan.files) {
    const abs = path.resolve(root, fileChange.path);

    if (fileChange.create) {
      // We created the file — delete it
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
      continue;
    }

    if (fileChange.append !== undefined) {
      if (!fs.existsSync(abs)) continue;
      const current = fs.readFileSync(abs, 'utf8');
      // Try to remove the appended text (it may be at the end)
      const idx = current.lastIndexOf(fileChange.append);
      if (idx === -1) {
        throw new Error(`appended text not found in ${fileChange.path}`);
      }
      const reverted = current.slice(0, idx) + current.slice(idx + fileChange.append.length);
      fs.writeFileSync(abs, reverted, 'utf8');
      continue;
    }

    // Standard edits — reverse find/replace
    if (!fs.existsSync(abs)) {
      throw new Error(`file no longer exists: ${fileChange.path}`);
    }
    let content = fs.readFileSync(abs, 'utf8');
    // Reverse in opposite order in case edits are positionally dependent
    const reversed = [...fileChange.edits].reverse();
    for (const e of reversed) {
      const newStr = e.replace;
      const oldStr = e._resolvedFind || e.find;
      if (!content.includes(newStr)) {
        throw new Error(`reverted text not found in ${fileChange.path} (file changed since fix)`);
      }
      content = content.replace(newStr, oldStr);
    }
    fs.writeFileSync(abs, content, 'utf8');
  }
}
