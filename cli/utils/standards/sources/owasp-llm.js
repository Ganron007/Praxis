/**
 * OWASP Top 10 for LLM Applications (2025).
 * https://genai.owasp.org/llm-top-10/
 */

export const name = 'owasp-llm';
export const version = '2025';
export const title = 'OWASP Top 10 for LLM Applications';
export const description = 'Most critical security risks for applications using large language models.';
export const url = 'https://genai.owasp.org/llm-top-10/';

export const controls = [
  { id: 'LLM01', title: 'Prompt Injection',                  description: 'User or indirect input manipulates LLM behavior, bypassing instructions.' },
  { id: 'LLM02', title: 'Sensitive Information Disclosure',  description: 'LLM reveals secrets, PII, or proprietary data via outputs.' },
  { id: 'LLM03', title: 'Supply Chain',                      description: 'Compromised models, datasets, plugins, or upstream packages.' },
  { id: 'LLM04', title: 'Data and Model Poisoning',          description: 'Tampered training, fine-tuning, or retrieval data biases the model.' },
  { id: 'LLM05', title: 'Improper Output Handling',          description: 'Downstream systems trust LLM output without validation/escaping.' },
  { id: 'LLM06', title: 'Excessive Agency',                  description: 'LLM granted excessive autonomy, permissions, or tool scope.' },
  { id: 'LLM07', title: 'System Prompt Leakage',             description: 'System prompts containing secrets or rules are exposed.' },
  { id: 'LLM08', title: 'Vector and Embedding Weaknesses',   description: 'RAG/vector stores leak data or accept poisoned embeddings.' },
  { id: 'LLM09', title: 'Misinformation',                    description: 'Confidently wrong outputs propagate as fact.' },
  { id: 'LLM10', title: 'Unbounded Consumption',             description: 'Resource exhaustion (cost, tokens, latency) via crafted prompts.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (owasp === 'ASI01' || /prompt.?inject|jailbreak|goal.?hijack/.test(rule + title)) ids.add('LLM01');
  if (cat === 'secrets' || cat === 'git-history' || cwe === 'CWE-200' || cwe === 'CWE-312' || cwe === 'CWE-522' || cwe === 'CWE-798' || owasp === 'ASI06') ids.add('LLM02');
  if (cat === 'supply-chain' || cat === 'deps' || owasp === 'ASI04') ids.add('LLM03');
  if (owasp === 'ASI05' || /poison|tamper/.test(rule + title)) ids.add('LLM04');
  if (cwe === 'CWE-79' || cwe === 'CWE-94' || cwe === 'CWE-116' || /output.?handl|unescaped/.test(rule + title)) ids.add('LLM05');
  if (cwe === 'CWE-269' || cwe === 'CWE-250' || owasp === 'ASI02' || owasp === 'ASI03') ids.add('LLM06');
  if (/system.?prompt|prompt.?leak/.test(rule + title)) ids.add('LLM07');
  if (/vector|embedding|rag\b|retrieval/.test(rule + title)) ids.add('LLM08');
  if (owasp === 'ASI10' || /halluc|misinform/.test(rule + title)) ids.add('LLM09');
  if (cat === 'api' || /rate.?limit|token.?abuse|unbounded|dos/.test(rule + title)) ids.add('LLM10');

  return [...ids];
}
