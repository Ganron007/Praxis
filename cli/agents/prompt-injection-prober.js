/**
 * Prompt Injection Prober
 * ========================
 *
 * Loads a probe corpus from cli/data/probes/prompt-injection-corpus.json and
 * scans source code for static-detectable signals that match each probe.
 *
 * The corpus replaces hardcoded patterns: new probes are added by editing
 * the JSON file. Each probe carries `tags` (e.g. ['LLM01', 'AML.T0051'])
 * which feed into the standards registry automatically — once the agent
 * tags a finding with the probe IDs, the per-finding `standards` field is
 * populated by the ScoringEngine.
 *
 * Maps to: OWASP LLM01/05/06/07/08, MITRE ATLAS T0043/T0051/T0053/T0054/T0057/T0070.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { BaseAgent, createFinding } from './base-agent.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CORPUS_PATH = path.resolve(__dirname, '..', 'data', 'probes', 'prompt-injection-corpus.json');

const SCAN_EXTS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.go', '.java', '.rs', '.php']);

let _cachedCorpus = null;

function loadCorpus() {
  if (_cachedCorpus) return _cachedCorpus;
  try {
    const raw = fs.readFileSync(CORPUS_PATH, 'utf-8');
    const data = JSON.parse(raw);
    const categoryById = {};
    for (const c of data.categories || []) categoryById[c.id] = c;
    const probes = (data.probes || []).map(p => {
      const cat = categoryById[p.category] || {};
      let regex;
      try {
        regex = compileProbeRegex(p.regex);
      } catch {
        regex = null;
      }
      return { ...p, patternSource: p.regex, regex, categoryTitle: cat.title || p.category, tags: cat.tags || [] };
    });

    // Overlay threat-pack probes from the merged intel feed (fetched via
    // `praxis intel update`). New attack-vector signatures arrive as data.
    try {
      const feed = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.praxis', 'threat-intel.json'), 'utf-8'));
      const packProbes = feed?.threatPack?.probes || [];
      for (const p of packProbes) {
        const cat = categoryById[p.category] || {};
        let regex;
        try { regex = compileProbeRegex(p.regex); } catch { regex = null; }
        probes.push({ ...p, patternSource: p.regex, regex, categoryTitle: cat.title || p.category, tags: cat.tags || [] });
      }
    } catch { /* no feed yet — bundled corpus only */ }

    _cachedCorpus = { version: data.version, probes };
    return _cachedCorpus;
  } catch {
    _cachedCorpus = { version: '0', probes: [] };
    return _cachedCorpus;
  }
}

function compileProbeRegex(pattern) {
  let flags = 'g';
  let body = pattern;
  const m = body.match(/^\(\?([imsux]+)\)/);
  if (m) {
    for (const f of m[1]) if ('imsu'.includes(f) && !flags.includes(f)) flags += f;
    body = body.slice(m[0].length);
  }
  // Scanner hardening: reject nested-quantifier constructs that risk
  // catastrophic backtracking on adversarial input.
  if (NESTED_QUANTIFIER.test(body)) {
    throw new Error('ReDoS-unsafe probe regex (nested quantifiers)');
  }
  return new RegExp(body, flags);
}

const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*[+*]\)[+*{]/;

export class PromptInjectionProber extends BaseAgent {
  constructor() {
    super(
      'PromptInjectionProber',
      'Probe-corpus-driven scan for prompt-injection patterns (OWASP LLM01, ATLAS T0043/T0051)',
      'llm'
    );
    this._corpus = loadCorpus();
    this.probeCount = this._corpus.probes.length;
  }

  shouldRun(recon) {
    if (!recon) return true;
    const langs = recon.languages instanceof Set ? [...recon.languages] : (recon.languages || []);
    if (langs.some(l => ['javascript', 'typescript', 'python', 'ruby', 'go', 'java', 'rust', 'php'].includes(l))) {
      return true;
    }
    return Boolean(recon.frameworks?.length || recon.apiRoutes?.length);
  }

  async analyze(context) {
    const findings = [];
    const probes = this._corpus.probes.filter(p => p.regex);
    if (probes.length === 0) return findings;

    const files = this.getFilesToScan(context).filter(f => SCAN_EXTS.has(path.extname(f).toLowerCase()));

    for (const file of files) {
      const content = this.readFile(file);
      if (!content) continue;
      const lines = content.split('\n');

      for (const probe of probes) {
        probe.regex.lastIndex = 0;
        let match;
        while ((match = probe.regex.exec(content)) !== null) {
          const idx = match.index;
          const before = content.slice(0, idx);
          const lineNum = before.split('\n').length;
          const lastNl = before.lastIndexOf('\n');
          const column = lastNl === -1 ? idx + 1 : idx - lastNl;
          const lineText = lines[lineNum - 1] || '';
          if (this.isSuppressed(lineText)) continue;

          const finding = createFinding({
            file,
            line: lineNum,
            column,
            severity: probe.severity || 'medium',
            category: 'llm',
            rule: `PROBE_${probe.id}`,
            title: probe.title,
            description: probe.description,
            matched: match[0].slice(0, 160),
            confidence: 'medium',
            cwe: 'CWE-77',
            owasp: 'ASI01',
            fix: probe.fix || 'Sanitize untrusted input before LLM prompt construction.',
          });
          finding.probe = { id: probe.id, category: probe.category, tags: probe.tags };
          findings.push(finding);

          if (!probe.regex.global) break;
          if (match.index === probe.regex.lastIndex) probe.regex.lastIndex++;
        }
      }
    }

    return findings;
  }
}

export const _internals = { loadCorpus, compileProbeRegex, CORPUS_PATH };
export default PromptInjectionProber;
