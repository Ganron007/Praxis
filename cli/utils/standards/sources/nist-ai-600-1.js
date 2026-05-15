/**
 * NIST AI 600-1 — Generative AI Profile (companion to AI RMF 1.0).
 * https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
 *
 * The profile lists actions tagged with prefixes for each RMF function
 * (GV/MP/MS/MG) tailored to GenAI. We use a representative subset.
 */

export const name = 'nist-ai-600-1';
export const version = '1.0';
export const title = 'NIST AI 600-1 (Generative AI Profile)';
export const description = 'GenAI-specific risk management actions complementing NIST AI RMF 1.0.';
export const url = 'https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf';

export const controls = [
  { id: 'GV-1.3-GAI', title: 'Govern: GenAI policies & procedures',     description: 'Establish policies addressing GenAI-specific risks.' },
  { id: 'GV-4.1-GAI', title: 'Govern: organizational responsibility',   description: 'Define roles for GenAI risk decisions and tool use.' },
  { id: 'MP-2.3-GAI', title: 'Map: dangerous/violent content risks',    description: 'Identify CBRN, malicious code, and harmful-output risks.' },
  { id: 'MP-5.1-GAI', title: 'Map: information integrity',              description: 'Identify confabulation, prompt injection, data integrity risks.' },
  { id: 'MS-2.6-GAI', title: 'Measure: harmful content / safety',       description: 'Assess outputs for harmful, biased, or unsafe content.' },
  { id: 'MS-2.7-GAI', title: 'Measure: security and adversarial robustness', description: 'Evaluate robustness against adversarial inputs and exfiltration.' },
  { id: 'MS-2.10-GAI', title: 'Measure: information security',          description: 'Test for leakage of training data, secrets, system prompts.' },
  { id: 'MG-2.2-GAI', title: 'Manage: data privacy & confidentiality',  description: 'Mitigate disclosure of PII and confidential data.' },
  { id: 'MG-3.2-GAI', title: 'Manage: third-party / supply chain',      description: 'Manage risks from third-party models, datasets, components.' },
  { id: 'MG-4.1-GAI', title: 'Manage: ongoing monitoring',              description: 'Continuous monitoring for new GenAI risks post-deployment.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (cat === 'agent-config' || cat === 'agentic') { ids.add('GV-1.3-GAI'); ids.add('GV-4.1-GAI'); }
  if (/prompt.?inject|jailbreak/.test(rule + title) || owasp === 'ASI01') { ids.add('MP-5.1-GAI'); ids.add('MS-2.7-GAI'); }
  if (cat === 'memory-poisoning' || cat === 'rag' || owasp === 'ASI05') ids.add('MP-5.1-GAI');
  if (cat === 'llm' && /toxic|harm|unsafe/.test(rule + title)) { ids.add('MP-2.3-GAI'); ids.add('MS-2.6-GAI'); }
  if (cat === 'secrets' || cwe === 'CWE-200' || cwe === 'CWE-312' || cwe === 'CWE-798' || owasp === 'ASI06') { ids.add('MG-2.2-GAI'); ids.add('MS-2.10-GAI'); }
  if (cat === 'supply-chain' || cat === 'deps' || owasp === 'ASI04') ids.add('MG-3.2-GAI');
  if (cat === 'mcp' || owasp === 'ASI08' || owasp === 'ASI10') ids.add('MG-4.1-GAI');

  return [...ids];
}
