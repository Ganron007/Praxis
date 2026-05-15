/**
 * ISO/IEC 42001:2023 — AI Management System (AIMS).
 * https://www.iso.org/standard/81230.html
 *
 * Annex A controls covering AI policy, resources, impact assessment,
 * data, lifecycle, third parties, and information for users.
 */

export const name = 'iso-42001';
export const version = '2023';
export const title = 'ISO/IEC 42001 (AI Management System)';
export const description = 'International standard for establishing, implementing, and maintaining an AI management system.';
export const url = 'https://www.iso.org/standard/81230.html';

export const controls = [
  { id: 'A.5.2',   title: 'AI policy',                            description: 'Documented policy governing AI development and use.' },
  { id: 'A.6.2.4', title: 'AI system impact assessment',          description: 'Assess impacts on individuals, groups, society.' },
  { id: 'A.6.2.6', title: 'AI system design — privacy & security', description: 'Embed privacy and security in AI system design.' },
  { id: 'A.7.4',   title: 'Quality of data for AI systems',       description: 'Ensure quality and integrity of training/inference data.' },
  { id: 'A.8.2',   title: 'Resources for AI systems',             description: 'Manage AI compute, models, and tooling assets.' },
  { id: 'A.8.4',   title: 'Tooling for AI systems',               description: 'Validate tools used in AI development.' },
  { id: 'A.9.2',   title: 'Information for users of AI systems',  description: 'Communicate intended use, limits, and risks.' },
  { id: 'A.10.2',  title: 'Allocation of responsibilities',       description: 'Assign responsibilities for AI suppliers/customers.' },
  { id: 'A.10.3',  title: 'Suppliers',                            description: 'Manage AI-relevant supplier relationships.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (cat === 'agent-config' || cat === 'agentic') ids.add('A.5.2');
  if (cat === 'memory-poisoning' || cat === 'rag') { ids.add('A.7.4'); ids.add('A.6.2.4'); }
  if (cat === 'secrets' || cwe === 'CWE-200' || cwe === 'CWE-312' || cwe === 'CWE-798' || owasp === 'ASI06') ids.add('A.6.2.6');
  if (/prompt.?inject|jailbreak/.test(rule + title) || owasp === 'ASI01') ids.add('A.6.2.6');
  if (cat === 'mcp' || cat === 'config') ids.add('A.8.4');
  if (owasp === 'ASI08' || /human.?oversight|missing.?confirmation/.test(rule + title)) ids.add('A.9.2');
  if (cat === 'supply-chain' || cat === 'deps' || owasp === 'ASI04') { ids.add('A.10.3'); ids.add('A.10.2'); }
  if (cat === 'llm') ids.add('A.8.2');

  return [...ids];
}
