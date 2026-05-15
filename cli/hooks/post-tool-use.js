#!/usr/bin/env node
/**
 * praxis PostToolUse Hook
 * ===========================
 *
 * Runs after Write / Edit / MultiEdit / NotebookEdit completes successfully.
 * Scans the written content for secrets and security issues, then returns
 * findings as a message that Claude Code injects back into the conversation.
 *
 * For Write and Edit, content is read from tool_input (no disk read needed).
 * For MultiEdit and NotebookEdit, the file is read from disk after the write.
 *
 * PostToolUse NEVER blocks — exit 0 always.
 * Empty stdout = silent (no findings or file skipped).
 *
 * Install via:  npx praxis hooks install
 */

import path from 'path';
import { existsSync, readFileSync } from 'fs';
import {
  scanCritical,
  scanHigh,
  SKIP_PATHS,
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
    process.exit(0);
  }

  const { tool_name, tool_input, tool_result_is_error } = payload;

  if (tool_result_is_error) process.exit(0);
  if (!['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(tool_name)) process.exit(0);

  const filePath = tool_input && (tool_input.file_path || tool_input.notebook_path || tool_input.path);
  if (!filePath) process.exit(0);

  // Skip example/sample env files entirely
  if (ENV_EXAMPLE_RE.test(filePath)) process.exit(0);

  // Skip test fixtures, mocks, etc.
  if (SKIP_PATHS.some(p => p.test(filePath))) process.exit(0);

  // .env files: secrets are expected — no secret scan, but gitignore already
  // warned in PreToolUse. Silent here.
  if (ENV_FILE_RE.test(filePath)) process.exit(0);

  // Get content to scan
  const content = getContent(tool_name, tool_input, filePath);
  if (!content) process.exit(0);

  // Run scans
  const critical = scanCritical(content);
  const high = scanHigh(content);

  if (critical.length === 0 && high.length === 0) process.exit(0);

  // Format advisory message for Claude's context
  const lines = [
    `[praxis] Security findings in ${path.basename(filePath)}:`,
    '',
  ];

  if (critical.length > 0) {
    lines.push('CRITICAL — rotate these credentials immediately:');
    for (const { name, line } of critical) {
      lines.push(`  • ${name}${line ? ` (line ${line})` : ''}`);
    }
    lines.push('');
  }

  if (high.length > 0) {
    lines.push('HIGH — review these:');
    for (const { name } of high) {
      lines.push(`  • ${name}`);
    }
    lines.push('');
  }

  lines.push('Run `npx praxis scan .` for full details and auto-fix options.');

  process.stdout.write(lines.join('\n'));
  process.exit(0);
}

// =============================================================================
// Helpers
// =============================================================================

/**
 * Get the content to scan.
 * Prefer tool_input (avoids a disk read) for Write and Edit.
 * Fall back to disk read for MultiEdit and NotebookEdit.
 */
function getContent(toolName, input, filePath) {
  if (toolName === 'Write' && input?.content) {
    return input.content;
  }
  if (toolName === 'Edit' && input?.new_string) {
    // For Edit, scan the full file so we catch pre-existing issues too
    return readFromDisk(filePath);
  }
  // MultiEdit and NotebookEdit — read the final state from disk
  return readFromDisk(filePath);
}

function readFromDisk(filePath) {
  try {
    if (!existsSync(filePath)) return null;
    return readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function readStdin() {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY) return resolve('');
    const chunks = [];
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => chunks.push(chunk));
    process.stdin.on('end', () => resolve(chunks.join('')));
    process.stdin.on('error', reject);
    setTimeout(() => resolve(''), 3000);
  });
}

main().catch(() => process.exit(0));
