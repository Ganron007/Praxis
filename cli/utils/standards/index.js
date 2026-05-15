/**
 * Standards registry.
 *
 * Each standard is a self-contained ESM module exporting:
 *   name, version, title, description, url, controls, mapFinding(finding)
 *
 * `mapFindingToStandards(finding)` returns:
 *   { 'owasp-llm': ['LLM01'], 'mitre-atlas': ['AML.T0051'], ... }
 *
 * Adding a standard: drop a file under ./sources, register in ALL_STANDARDS.
 */

import * as owaspLlm from './sources/owasp-llm.js';
import * as mitreAtlas from './sources/mitre-atlas.js';
import * as nistAi6001 from './sources/nist-ai-600-1.js';
import * as avid from './sources/avid.js';
import * as owaspMl from './sources/owasp-ml.js';
import * as euAiAct from './sources/eu-ai-act.js';
import * as iso42001 from './sources/iso-42001.js';
import * as googleSaif from './sources/google-saif.js';

export const ALL_STANDARDS = [
  owaspLlm,
  mitreAtlas,
  nistAi6001,
  avid,
  owaspMl,
  euAiAct,
  iso42001,
  googleSaif,
];

export function listStandards() {
  return ALL_STANDARDS.map(s => ({
    name: s.name,
    version: s.version,
    title: s.title,
    description: s.description,
    url: s.url,
    controlCount: (s.controls || []).length,
  }));
}

export function getStandard(name) {
  return ALL_STANDARDS.find(s => s.name === name) || null;
}

/**
 * Tag a single finding with all standard control IDs it maps to.
 * @returns {Object<string, string[]>} keyed by standard name; empty arrays omitted.
 */
export function mapFindingToStandards(finding) {
  const out = {};
  for (const s of ALL_STANDARDS) {
    let ids;
    try {
      ids = s.mapFinding(finding) || [];
    } catch {
      ids = [];
    }
    if (ids.length > 0) out[s.name] = ids;
  }
  return out;
}

/**
 * Aggregate coverage across a finding set.
 * Returns:
 *   {
 *     [standardName]: {
 *       title, version, totalControls, flaggedControls, coverage,
 *       controls: [{ id, title, findingCount, status }]
 *     }
 *   }
 */
export function getStandardsSummary(findings = []) {
  const summary = {};

  for (const s of ALL_STANDARDS) {
    summary[s.name] = {
      name: s.name,
      title: s.title,
      version: s.version,
      url: s.url,
      totalControls: (s.controls || []).length,
      flaggedControls: 0,
      coverage: `0/${(s.controls || []).length}`,
      controls: (s.controls || []).map(c => ({ ...c, findingCount: 0, status: 'clear' })),
    };
  }

  for (const f of findings) {
    const tagged = mapFindingToStandards(f);
    for (const [stdName, ids] of Object.entries(tagged)) {
      const std = summary[stdName];
      if (!std) continue;
      for (const id of ids) {
        const ctrl = std.controls.find(c => c.id === id);
        if (ctrl) {
          ctrl.findingCount += 1;
          ctrl.status = 'flagged';
        }
      }
    }
  }

  for (const std of Object.values(summary)) {
    std.flaggedControls = std.controls.filter(c => c.findingCount > 0).length;
    std.coverage = `${std.flaggedControls}/${std.totalControls}`;
  }

  return summary;
}

/**
 * Filter a finding list to only those tagged with a given standard (and
 * optionally a specific control within that standard).
 */
export function filterFindingsByStandard(findings, standardName, controlId = null) {
  return findings.filter(f => {
    const tagged = f.standards || mapFindingToStandards(f);
    const ids = tagged[standardName];
    if (!ids || ids.length === 0) return false;
    if (controlId) return ids.includes(controlId);
    return true;
  });
}
