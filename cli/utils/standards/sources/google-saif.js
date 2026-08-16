/**
 * Google Secure AI Framework (SAIF).
 * https://safety.google/cybersecurity-advancements/saif/
 *
 * Six core elements for securing AI systems end-to-end.
 */

export const name = 'google-saif';
export const version = '1.0';
export const title = 'Google Secure AI Framework (SAIF)';
export const description = 'Conceptual framework for securing AI systems across foundations, detection, defense, controls, adaptation, and context.';
export const url = 'https://safety.google/cybersecurity-advancements/saif/';

export const controls = [
  { id: 'SAIF-1', title: 'Expand strong security foundations to the AI ecosystem', description: 'Apply secure-by-default infra and IAM to AI workloads.' },
  { id: 'SAIF-2', title: 'Extend detection and response to AI threats',            description: 'Bring AI into the SOC: monitor model I/O, prompt anomalies.' },
  { id: 'SAIF-3', title: 'Automate defenses to keep pace with new threats',        description: 'Automate scanning, patching, and adversarial testing.' },
  { id: 'SAIF-4', title: 'Harmonize platform-level controls across AI systems',    description: 'Consistent controls across model serving, RAG, and agents.' },
  { id: 'SAIF-5', title: 'Adapt controls and create faster feedback loops',        description: 'Continuously tune mitigations using deployment signals.' },
  { id: 'SAIF-6', title: 'Contextualize AI risks in surrounding business processes', description: 'Tie AI risk to actual use case, data, and business impact.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (cat === 'auth' || cat === 'config' || cat === 'secrets' || /^CWE-(287|306|269|250|798|312)$/.test(cwe)) ids.add('SAIF-1');
  if (/log.?inject|missing.?logg|silent|hide.?output/.test(rule + title) || owasp === 'ASI06') ids.add('SAIF-2');
  if (cat === 'supply-chain' || cat === 'deps' || cat === 'git-history' || owasp === 'ASI04') ids.add('SAIF-3');
  if (/mcp|tool.?poison|rag\b|retrieval|vector.?store|agent.?config|\.cursorrules|CLAUDE\.md/.test(rule + title) || cat === 'agentic') ids.add('SAIF-4');
  if (owasp === 'ASI05' || owasp === 'ASI10' || /poison|tamper|memory/.test(rule + title)) ids.add('SAIF-5');
  if (owasp === 'ASI08' || cat === 'llm') ids.add('SAIF-6');

  return [...ids];
}
