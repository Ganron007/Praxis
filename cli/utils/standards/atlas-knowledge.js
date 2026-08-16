/**
 * MITRE ATLAS knowledge lookup — vendored enrichment data.
 *
 * Loads cli/data/atlas-knowledge.json (Apache-2.0, The MITRE Corporation,
 * snapshot 2026-04). Provides hydrated technique details for reports:
 * technique name/description/URL, parent tactics, mitigations (with
 * parent-technique fallback), and real-world case studies.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_PATH = path.join(__dirname, '..', '..', 'data', 'atlas-knowledge.json');

let _cache = null;

function load() {
  if (_cache) return _cache;
  try {
    _cache = JSON.parse(fs.readFileSync(DATA_PATH, 'utf-8'));
  } catch {
    _cache = { entities: {}, snapshot: 'unknown' };
  }
  return _cache;
}

export function atlasSnapshot() {
  return load().snapshot || 'unknown';
}

export function atlasAttribution() {
  return load()._attribution || null;
}

export function isKnownTechnique(id) {
  const e = load().entities[id];
  return Boolean(e && e.entity === 'technique');
}

/**
 * Hydrate a technique with readable references. Mitigations fall back to the
 * parent technique when the (sub-)technique itself carries none.
 */
export function getTechniqueDetails(id) {
  const data = load();
  const entity = data.entities[id];
  if (!entity) return null;

  const out = {
    id,
    name: entity.name,
    description: entity.description,
    url: entity.url || `https://atlas.mitre.org/techniques/${id}`,
    tactics: [],
    mitigations: [],
    caseStudies: [],
  };

  for (const t of entity.parentTactics || []) {
    const tactic = data.entities[t];
    if (tactic) out.tactics.push({ id: t, name: tactic.name, url: tactic.url });
  }

  let mitigationIds = entity.parentMitigations || [];
  if (mitigationIds.length === 0 && (entity.parentTechniques || []).length > 0) {
    const parent = data.entities[entity.parentTechniques[0]];
    mitigationIds = parent?.parentMitigations || [];
  }
  for (const m of mitigationIds) {
    const mit = data.entities[m];
    if (mit) out.mitigations.push({ id: m, name: mit.name, url: mit.url });
  }

  for (const c of entity.parentCaseStudies || []) {
    const cs = data.entities[c];
    if (cs) out.caseStudies.push({ id: c, name: cs.name, url: cs.url });
  }

  return out;
}

export function listTechniques() {
  const data = load();
  return Object.values(data.entities).filter(e => e.entity === 'technique');
}
