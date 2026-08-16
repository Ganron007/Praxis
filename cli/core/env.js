/**
 * Minimal .env loader (no dependency).
 *
 * Loads KEY=VALUE pairs from <rootPath>/.env into process.env without
 * overriding variables that are already set (real environment wins).
 * Lines starting with # and blank lines are ignored; values may be
 * wrapped in single or double quotes.
 */

import fs from 'fs';
import path from 'path';

export function loadDotEnv(rootPath) {
  try {
    const envPath = path.join(rootPath, '.env');
    if (!fs.existsSync(envPath)) return false;

    const content = fs.readFileSync(envPath, 'utf-8');
    for (const line of content.split('\n')) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m) continue;
      const key = m[1];
      let val = m[2].trim();
      if (
        (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
        (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
      ) {
        val = val.slice(1, -1);
      }
      if (process.env[key] === undefined || process.env[key] === '') {
        process.env[key] = val;
      }
    }
    return true;
  } catch {
    return false;
  }
}
