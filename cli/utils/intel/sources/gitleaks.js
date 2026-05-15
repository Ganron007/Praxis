/**
 * Gitleaks rules — community-maintained secret detection regex set.
 * https://github.com/gitleaks/gitleaks
 *
 * We sync the upstream rules list (TOML config) and convert to praxis's
 * SECRET_PATTERNS shape. Rules already present (by name) in our hardcoded
 * patterns.js are skipped to avoid duplicates.
 *
 * Result: ~150 → ~400 secret detection patterns without code changes.
 */

import { fetchText } from '../http.js';

const URL = 'https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml';
const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7d

export const name = 'gitleaks';
export const tier = 'core';
export const description = 'Gitleaks regex rule set (additional secret patterns)';

export async function fetchAll() {
  const toml = await fetchText(URL);
  const rules = parseRules(toml);
  return {
    sourceUrl: URL,
    count: rules.length,
    rules,
  };
}

/**
 * Tiny TOML parser — only handles what gitleaks.toml uses:
 *   [[rules]]
 *   id = "..."
 *   description = "..."
 *   regex = '''...'''
 *   keywords = ["..."]
 *
 * Avoids pulling in a TOML dependency for one file.
 */
function parseRules(toml) {
  const rules = [];
  const sections = toml.split(/^\[\[rules\]\]\s*$/m).slice(1);

  for (const section of sections) {
    const lines = section.split('\n');
    const rule = {};
    let collectingMultiline = null;
    let multilineBuf = '';

    for (const line of lines) {
      if (collectingMultiline) {
        if (line.includes("'''")) {
          multilineBuf += line.slice(0, line.indexOf("'''"));
          rule[collectingMultiline] = multilineBuf;
          collectingMultiline = null;
          multilineBuf = '';
        } else {
          multilineBuf += line + '\n';
        }
        continue;
      }

      // Stop at next section
      if (/^\[/.test(line.trim())) break;

      const m = line.match(/^\s*(id|description|regex|tags)\s*=\s*(.*)$/);
      if (!m) continue;
      const [, key, rawVal] = m;
      const val = rawVal.trim();

      if (val.startsWith("'''")) {
        if (val.length > 3 && val.endsWith("'''")) {
          rule[key] = val.slice(3, -3);
        } else {
          collectingMultiline = key;
          multilineBuf = val.slice(3) + '\n';
        }
      } else if (val.startsWith('"') || val.startsWith("'")) {
        rule[key] = val.slice(1, -1);
      } else if (val.startsWith('[')) {
        rule[key] = val.replace(/[[\]"']/g, '').split(',').map(s => s.trim()).filter(Boolean);
      } else {
        rule[key] = val;
      }
    }

    if (rule.id && rule.regex) {
      rules.push({
        id: rule.id,
        description: rule.description || rule.id,
        regex: rule.regex,
        tags: Array.isArray(rule.tags) ? rule.tags : [],
      });
    }
  }

  return rules;
}

export const TTL = TTL_MS;
