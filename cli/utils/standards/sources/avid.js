/**
 * AVID — AI Vulnerability Database taxonomy.
 * https://avidml.org/
 *
 * AVID classifies vulnerabilities under three top-level categories:
 *   S — Security    P — Performance    E — Ethics
 */

export const name = 'avid';
export const version = '2024';
export const title = 'AI Vulnerability Database (AVID) Taxonomy';
export const description = 'Open taxonomy for AI failure modes across security, performance, and ethics.';
export const url = 'https://avidml.org/';

export const controls = [
  { id: 'S0100', title: 'Software Vulnerability',          description: 'Classical software flaws in AI systems (injection, IDOR, etc.).' },
  { id: 'S0200', title: 'Supply Chain Compromise',         description: 'Tampered model, dataset, or upstream package.' },
  { id: 'S0301', title: 'Information Leakage',             description: 'Model leaks training data, secrets, or system prompts.' },
  { id: 'S0400', title: 'Model Bypass / Evasion',          description: 'Crafted inputs bypass model safety or filters.' },
  { id: 'S0500', title: 'Exfiltration via Model Outputs',  description: 'Adversary uses model channel to exfiltrate data.' },
  { id: 'P0201', title: 'Robustness — Adversarial',        description: 'Model degrades under adversarial / OOD inputs.' },
  { id: 'P0204', title: 'Data Drift',                      description: 'Inputs diverge from training distribution.' },
  { id: 'P0301', title: 'Hallucination / Confabulation',   description: 'Confidently incorrect outputs.' },
  { id: 'E0101', title: 'Group Fairness',                  description: 'Outputs disadvantage protected groups.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (cat === 'injection' || cat === 'auth' || cat === 'config' || /^CWE-/.test(cwe)) ids.add('S0100');
  if (cat === 'supply-chain' || cat === 'deps' || owasp === 'ASI04') ids.add('S0200');
  if (cat === 'secrets' || cat === 'git-history' || cwe === 'CWE-200' || cwe === 'CWE-312' || owasp === 'ASI06') ids.add('S0301');
  if (/jailbreak|prompt.?inject|bypass/.test(rule + title) || owasp === 'ASI01') ids.add('S0400');
  if (owasp === 'ASI05' || /poison|tamper|memory/.test(rule + title)) ids.add('P0201');
  if (/retrieval|vector.?store|rag\b|embedding/.test(rule + title)) ids.add('S0500');
  if (/halluc|confabul|misinform/.test(rule + title) || owasp === 'ASI10') ids.add('P0301');
  if (/bias|fairness|discriminat/.test(rule + title)) ids.add('E0101');

  return [...ids];
}
