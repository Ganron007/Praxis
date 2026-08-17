/**
 * EU AI Act (Regulation (EU) 2024/1689).
 * https://eur-lex.europa.eu/eli/reg/2024/1689/oj
 *
 * Control text authored by Praxis from the public text of the Regulation
 * (EUR-Lex). For static analysis we tag findings against the cybersecurity,
 * transparency, data-governance, oversight, and post-market monitoring
 * obligations most relevant to code-level signals.
 */

export const name = 'eu-ai-act';
export const version = '2024/1689';
export const title = 'EU AI Act';
export const description = 'Regulation laying down harmonised rules on artificial intelligence in the EU.';
export const url = 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj';

export const controls = [
  { id: 'Art.5',   title: 'Prohibited AI practices',                  description: 'Subliminal/manipulative techniques, exploitative, social scoring, and similar prohibited uses (Art. 5(1)(a)-(h)).' },
  { id: 'Art.9',   title: 'Risk management system',                   description: 'Continuous risk management for high-risk systems covering identification, analysis, mitigation, and testing (Art. 9).' },
  { id: 'Art.10',  title: 'Data and data governance',                 description: 'Training/validation data must meet quality, integrity, and relevance criteria; governance for bias and gaps (Art. 10).' },
  { id: 'Art.11',  title: 'Technical documentation',                  description: 'Documentation demonstrating compliance with high-risk requirements before and during market placement (Art. 11, Annex IV).' },
  { id: 'Art.12',  title: 'Record keeping / logging',                 description: 'Automatic logging of system events sufficient for post-market traceability and oversight (Art. 12).' },
  { id: 'Art.13',  title: 'Transparency to deployers',                description: 'High-risk AI must be designed for transparent operation; instructions for use (Art. 13).' },
  { id: 'Art.14',  title: 'Human oversight',                          description: 'Effective oversight by natural persons during AI use; intervention and override capability (Art. 14).' },
  { id: 'Art.15',  title: 'Accuracy, robustness and cybersecurity',   description: 'AI systems must be resilient against errors, faults, and adversarial manipulation (Art. 15).' },
  { id: 'Art.17',  title: 'Quality management system',                description: 'Provider QMS covering design control, verification, data management, and post-market monitoring (Art. 17).' },
  { id: 'Art.25',  title: 'Responsibilities along the value chain',   description: 'Obligations distributed among providers, deployers, importers, and distributors (Art. 25).' },
  { id: 'Art.26',  title: 'Obligations of deployers', detectable: false,                 description: 'Deployers must use high-risk systems per instructions, ensure input relevance, and monitor operation (Art. 26).' },
  { id: 'Art.27',  title: 'Fundamental rights impact assessment', detectable: false,     description: 'Deployers of high-risk systems assess impact on fundamental rights before deployment (Art. 27).' },
  { id: 'Art.49',  title: 'Registration', detectable: false,                             description: 'High-risk systems registered in the EU database before market placement (Art. 49).' },
  { id: 'Art.50',  title: 'Transparency for GenAI / chatbots',        description: 'Disclose AI interaction; mark synthetic and deepfake content (Art. 50).' },
  { id: 'Art.53',  title: 'GPAI provider obligations',                description: 'General-purpose AI model documentation, copyright policy, training-data summary (Art. 53).' },
  { id: 'Art.55',  title: 'GPAI systemic-risk obligations',           description: 'Adversarial testing, incident reporting, and cybersecurity for systemic-risk models (Art. 55).' },
  { id: 'Art.72',  title: 'Post-market monitoring',                   description: 'Continuous monitoring of deployed AI for new risks; corrective action and incident reporting (Art. 72).' },
  { id: 'Art.73',  title: 'Reporting of serious incidents',           description: 'Serious incidents reported to market surveillance authorities, with investigations (Art. 73).' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();
  const text = rule + title;

  // Art. 5 — prohibited-practice adjacent signals (deception, manipulation, social scoring)
  if (/social.?scor|subliminal|manipulat|deceptiv|emotion.?recogn/.test(text)) ids.add('Art.5');

  // Art. 9/10 — data governance, model/data/context poisoning, RAG content
  if (/poison|embedding|rag\b|retrieval|memory/.test(text)) {
    ids.add('Art.9'); ids.add('Art.10');
  }

  // Art. 11/17 — technical documentation / QMS evidence gaps
  if (/no.?model.?card|missing.?documentation|no.?readme/.test(text)) ids.add('Art.11');
  if (/unpinned|attestation|unsigned|integrity.?hash/.test(text)) ids.add('Art.17');

  // Art. 12 — logging / record keeping
  if (/no.?logging|no.?observability|telemetry|no.?audit.?log/.test(text)) ids.add('Art.12');

  // Art. 13 — transparency / opaqueness / system prompt leakage
  if (/system.?prompt.?leak|opaqu|disclos|transparen/.test(text)) ids.add('Art.13');

  // Art. 14 — human oversight / auto-approval / excessive agency
  if (owasp === 'ASI08' || /human.?oversight|auto.?accept|yolo|excessive.?agency|no.?approval|permissionless/.test(text)) ids.add('Art.14');

  // Art. 15 — accuracy/robustness/cybersecurity (all technical vuln classes)
  if (cat === 'injection' || cat === 'supply-chain' || cat === 'auth' || cat === 'config'
      || /prompt.?inject|jailbreak/.test(text) || owasp === 'ASI01' || owasp === 'ASI04'
      || cwe === 'CWE-94' || cwe === 'CWE-78' || cwe === 'CWE-502') ids.add('Art.15');

  // Art. 25/26 — value chain, third-party components, deployer obligations
  if (/third.?party|supplier|vendor|deployer/.test(text) && (cat === 'supply-chain' || /mcp/.test(text))) ids.add('Art.25');

  // Art. 50 — GenAI/chatbot disclosure, synthetic content
  if (/chatbot|user.?facing|disclos|synthetic|deepfake/.test(text)) ids.add('Art.50');

  // Art. 53/55 — GPAI obligations, model provenance, systemic risk
  if (cat === 'supply-chain' && /(model|dataset|gpai|foundation|training.?data)/.test(text)) ids.add('Art.53');
  if (owasp === 'ASI10' || /systemic.?risk|capabilit|frontier/.test(text)) ids.add('Art.55');

  // Art. 72/73 — post-market monitoring / incident reporting / MCP runtime risk
  if (/mcp|tool.?poison/.test(text) || owasp === 'ASI06' || /post.?market|incident.?report|no.?monitoring/.test(text)) {
    ids.add('Art.72'); ids.add('Art.73');
  }

  return [...ids];
}
