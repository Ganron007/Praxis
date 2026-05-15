#!/usr/bin/env node
/**
 * praxis PreToolUse Hook
 * ==========================
 *
 * Runs before every Claude Code tool call. Blocks:
 *   - Write / Edit / MultiEdit / NotebookEdit: content containing critical secrets
 *     (unless the target is a .env file — secrets belong there)
 *   - Bash: known-dangerous command patterns
 *
 * Protocol (claw-code / Claude Code hooks spec):
 *   - Input:  JSON payload on stdin
 *   - Exit 0: allow the tool to run (stdout = optional advisory message)
 *   - Exit 2: BLOCK the tool (stdout = reason shown to Claude and user)
 *   - Exit 1: warn but allow (stdout = warning message)
 *
 * Install via:  npx praxis hooks install
 */

import path from 'path';
import fs from 'fs';
import {
  scanCritical,
  buildFixSuggestion,
  DANGEROUS_BASH_PATTERNS,
  ENV_FILE_RE,
  ENV_EXAMPLE_RE,
} from './patterns.js';

// =============================================================================
// Main
// =============================================================================

async function main() {
  let payload;
  try {
    const raw = await readStdin();
    payload = JSON.parse(raw);
  } catch {
    process.exit(0); // can't parse → allow
  }

  const { tool_name, tool_input } = payload;

  // ── File write hooks (Write / Edit / MultiEdit / NotebookEdit) ───────────
  if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(tool_name)) {
    const filePath = tool_input && (tool_input.file_path || tool_input.notebook_path || tool_input.path);

    // .env.example / .env.sample — purely documentation, skip all checks
    if (filePath && ENV_EXAMPLE_RE.test(filePath)) {
      process.exit(0);
    }

    // .env / .env.local / .env.production — secrets SHOULD be here
    // Allow write, but warn if .gitignore doesn't cover the file
    if (filePath && ENV_FILE_RE.test(filePath)) {
      const warning = checkEnvGitignore(filePath);
      if (warning) {
        process.stdout.write(warning);
        process.exit(1); // warn but allow
      }
      process.exit(0);
    }

    const content = extractContent(tool_name, tool_input);
    if (content) {
      const hits = scanCritical(content);
      if (hits.length > 0) {
        process.stdout.write(buildBlockMessage(hits, filePath));
        process.exit(2);
      }
    }
  }

  // ── Bash hooks ─────────────────────────────────────────────────────────────
  if (tool_name === 'Bash') {
    const command = tool_input?.command ? String(tool_input.command) : '';
    if (command) {
      const hit = DANGEROUS_BASH_PATTERNS.find(p => p.re.test(command));
      if (hit) {
        process.stdout.write(
          `praxis blocked this command — ${hit.name}\n\n${hit.reason}`
        );
        process.exit(2);
      }
    }
  }

  process.exit(0);
}

// =============================================================================
// Helpers
// =============================================================================

function extractContent(toolName, input) {
  if (!input) return null;
  switch (toolName) {
    case 'Write':
      return input.content || null;
    case 'Edit':
      return input.new_string || null;
    case 'MultiEdit':
      return Array.isArray(input.edits)
        ? input.edits.map(e => e.new_string || '').join('\n')
        : null;
    case 'NotebookEdit':
      // NotebookEdit passes new cell source as new_source or source
      return input.new_source || input.source || input.cell_source || null;
    default:
      return null;
  }
}

function buildBlockMessage(hits, filePath) {
  const ext = filePath ? path.extname(filePath).toLowerCase() : '.js';
  const lines = [
    `praxis blocked this write — critical secret(s) detected:`,
    '',
  ];

  for (const { name, line, envVar } of hits) {
    const fix = buildFixSuggestion(envVar, filePath || '');
    lines.push(`  • ${name} on line ${line}`);
    lines.push(`    Fix: replace with ${fix}`);
    lines.push(`    Add to .env: ${envVar}=<your_value>`);
    lines.push('');
  }

  lines.push('Run `npx praxis scan .` for a full report.');
  return lines.join('\n');
}

/**
 * Check if a .env file is covered by .gitignore.
 * Returns a warning string if not covered, null if OK.
 */
function checkEnvGitignore(envFilePath) {
  const dir = path.dirname(path.resolve(envFilePath));
  const gitignorePath = path.join(dir, '.gitignore');

  // Walk up to repo root looking for .gitignore
  const roots = [dir, path.dirname(dir), path.dirname(path.dirname(dir))];
  for (const root of roots) {
    const gi = path.join(root, '.gitignore');
    if (!fs.existsSync(gi)) continue;
    try {
      const content = fs.readFileSync(gi, 'utf8');
      const lines = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      const basename = path.basename(envFilePath);
      const covered = lines.some(l =>
        l === '.env' ||
        l === basename ||
        l === '.env*' ||
        l === '*.env' ||
        l === '.env.*' ||
        (l.startsWith('.env') && basename.startsWith(l.replace('*', '')))
      );
      if (covered) return null;
      return (
        `praxis: ${basename} is not in .gitignore — secrets could be committed.\n` +
        `Add this line to ${gi}:\n  .env*\n`
      );
    } catch { /* ignore read errors */ }
  }

  // No .gitignore found at all
  return (
    `praxis: no .gitignore found. Create one and add ".env*" to prevent ` +
    `secrets from being committed.\n`
  );
}

function readStdin() {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY) return resolve('');
    const chunks = [];
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => chunks.push(chunk));
    process.stdin.on('end', () => resolve(chunks.join('')));
    process.stdin.on('error', reject);
    setTimeout(() => resolve(''), 3000); // never hang Claude Code
  });
}

main().catch(() => process.exit(0)); // never crash — silently allow on error
