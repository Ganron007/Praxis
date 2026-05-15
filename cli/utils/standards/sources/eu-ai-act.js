/**
 * EU AI Act (Regulation (EU) 2024/1689).
 * https://eur-lex.europa.eu/eli/reg/2024/1689/oj
 *
 * For static analysis we tag findings against the cybersecurity, transparency,
 * data-governance, and post-market monitoring obligations most relevant to
 * code-level signals.
 */

export const name = 'eu-ai-act';
export const version = '2024/1689';
export const title = 'EU AI Act';
export const description = 'Regulation laying down harmonised rules on artificial intelligence in the EU.';
export const url = 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj';

export const controls = [
  { id: 'Art.10',  title: 'Data and data governance',                  description: 'Training/validation data must meet quality and integrity criteria.' },
  { id: 'Art.13',  title: 'Transparency to deployers',                  description: 'High-risk AI must be designed for transparent operation.' },
  { id: 'Art.14',  title: 'Human oversight',                            description: 'Effective oversight by natural persons during AI use.' },
  { id: 'Art.15',  title: 'Accuracy, robustness and cybersecurity',     description: 'AI systems must be resilient against errors and adversarial use.' },
  { id: 'Art.50',  title: 'Transparency for GenAI / chatbots',          description: 'Disclose AI interaction; mark synthetic content.' },
  { id: 'Art.53',  title: 'GPAI provider obligations',                  description: 'Documentation, copyright, training-data summary.' },
  { id: 'Art.55',  title: 'GPAI systemic-risk obligations',             description: 'Adversarial testing, incident reporting for systemic-risk models.' },
  { id: 'Art.72',  title: 'Post-market monitoring',                     description: 'Continuous monitoring of deployed AI for new risks.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (cat === 'memory-poisoning' || cat === 'rag') ids.add('Art.10');
  if (/system.?prompt.?leak|opaqu/.test(rule + title)) ids.add('Art.13');
  if (owasp === 'ASI08' || /human.?oversight|auto.?accept|yolo/.test(rule + title)) ids.add('Art.14');
  if (cat === 'injection' || cat === 'supply-chain' || cat === 'auth' || cat === 'config' || /prompt.?inject|jailbreak/.test(rule + title) || owasp === 'ASI01' || owasp === 'ASI04' || cwe === 'CWE-94' || cwe === 'CWE-78') ids.add('Art.15');
  if (cat === 'agentic' && /chatbot|user.?facing|disclos/.test(rule + title)) ids.add('Art.50');
  if (cat === 'supply-chain' && /(model|dataset|gpai|foundation)/.test(rule + title)) ids.add('Art.53');
  if (owasp === 'ASI10' || /systemic.?risk|capabilit/.test(rule + title)) ids.add('Art.55');
  if (cat === 'mcp' || owasp === 'ASI06') ids.add('Art.72');

  return [...ids];
}
