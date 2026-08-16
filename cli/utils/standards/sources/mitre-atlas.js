/**
 * MITRE ATLAS — Adversarial Threat Landscape for AI Systems.
 * https://atlas.mitre.org/
 *
 * Subset of techniques observable from static code/config analysis.
 * Enriched with the vendored ATLAS knowledge snapshot (see atlas-knowledge.js).
 */

import { getTechniqueDetails, atlasSnapshot, isKnownTechnique } from '../atlas-knowledge.js';

export const name = 'mitre-atlas';
export const version = '2024';
export const title = 'MITRE ATLAS';
export const description = 'Adversarial tactics, techniques, and case studies for AI systems.';
export const url = 'https://atlas.mitre.org/';
export const enrichmentSnapshot = () => atlasSnapshot();

export { getTechniqueDetails, atlasSnapshot, isKnownTechnique };

export const controls = [
  { id: 'AML.T0010', title: 'ML Supply Chain Compromise',     description: 'Adversary compromises models/datasets/dependencies to gain access.' },
  { id: 'AML.T0018', title: 'Manipulate AI Model',            description: 'Modify deployed model parameters or artifacts.' },
  { id: 'AML.T0024', title: 'Exfiltration via ML Inference',  description: 'Leak training data or system info through inference outputs.' },
  { id: 'AML.T0034', title: 'ML Model Poisoning',             description: 'Insert poisoned data into training/fine-tuning pipeline.' },
  { id: 'AML.T0040', title: 'ML Model Inference API Access',  description: 'Abuse exposed inference APIs for evasion/extraction.' },
  { id: 'AML.T0043', title: 'Craft Adversarial Data',         description: 'Carefully crafted input bypasses model decision boundaries.' },
  { id: 'AML.T0048', title: 'External Harms',                 description: 'AI output causes financial, reputational, or societal damage.' },
  { id: 'AML.T0051', title: 'LLM Prompt Injection',           description: 'Direct or indirect prompt injection alters LLM behavior.' },
  { id: 'AML.T0053', title: 'LLM Plugin Compromise',          description: 'Malicious or vulnerable plugin/tool exposed to the LLM.' },
  { id: 'AML.T0054', title: 'LLM Jailbreak',                  description: 'Bypass safety alignment via crafted prompts or roleplay.' },
  { id: 'AML.T0057', title: 'LLM Data Leakage',               description: 'LLM emits training data, secrets, or system prompts.' },
  { id: 'AML.T0070', title: 'RAG Poisoning',                  description: 'Inject malicious documents into retrieval index.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (cat === 'supply-chain' || cat === 'deps' || owasp === 'ASI04') ids.add('AML.T0010');
  if (cat === 'memory-poisoning' || owasp === 'ASI05') { ids.add('AML.T0018'); ids.add('AML.T0034'); }
  if (cat === 'secrets' || cwe === 'CWE-200' || cwe === 'CWE-312' || owasp === 'ASI06') { ids.add('AML.T0024'); ids.add('AML.T0057'); }
  if (cat === 'api' && /llm|inference|model/.test(rule + title)) ids.add('AML.T0040');
  if (/jailbreak|dan|roleplay|ignore.?instructions/.test(rule + title)) ids.add('AML.T0054');
  if (/prompt.?inject|indirect.?inject/.test(rule + title) || owasp === 'ASI01') { ids.add('AML.T0043'); ids.add('AML.T0051'); }
  if (cat === 'mcp' || owasp === 'ASI02') ids.add('AML.T0053');
  if (cat === 'rag' || /retrieval|vector.?store/.test(rule + title)) ids.add('AML.T0070');
  if (owasp === 'ASI10') ids.add('AML.T0048');

  return [...ids];
}
