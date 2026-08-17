/**
 * ISO/IEC 42001:2023 — AI Management System (AIMS).
 * https://www.iso.org/standard/81230.html
 *
 * Control titles and structure follow the public Annex A outline; descriptions
 * are paraphrased by Praxis (ISO text is copyrighted — not reproduced).
 */

export const name = 'iso-42001';
export const version = '2023';
export const title = 'ISO/IEC 42001 (AI Management System)';
export const description = 'International standard for establishing, implementing, and maintaining an AI management system.';
export const url = 'https://www.iso.org/standard/81230.html';

export const controls = [
  // A.5 — Policies related to AI
  { id: 'A.5.2',   title: 'AI policy',                             description: 'Documented policy providing direction and support for AI development and use.' },
  { id: 'A.5.5',   title: 'AI policy review',                      description: 'Policy reviewed for continued suitability and updated when AI usage changes.' },
  // A.6 — Internal organization
  { id: 'A.6.1.2', title: 'AI roles and responsibilities',         description: 'Roles, responsibilities, and authorities for AI-related work defined and assigned.' },
  { id: 'A.6.2.4', title: 'AI system impact assessment',           description: 'Assess potential impacts of AI systems on individuals, groups of individuals, and societies.' },
  { id: 'A.6.2.6', title: 'AI system design — privacy & security', description: 'Privacy and security embedded in AI system design through the lifecycle.' },
  // A.7 — Resources for AI systems
  { id: 'A.7.2',   title: 'Resources',                             description: 'Resources needed across the AI system lifecycle are determined and provided.' },
  { id: 'A.7.4',   title: 'Quality of data for AI systems',        description: 'Data quality and integrity requirements defined for training, validation, and inference data.' },
  { id: 'A.7.6',   title: 'AI system documentation',               description: 'Documentation of the AI system and its lifecycle phases maintained and traceable.' },
  // A.8 — Assessment of AI system impact
  { id: 'A.8.2',   title: 'Resources for AI systems',              description: 'AI compute, models, and tooling assets managed as organizational resources.' },
  { id: 'A.8.4',   title: 'Tooling for AI systems',                description: 'Tools used in AI development, validation, and operation are evaluated and controlled.' },
  // A.9 — AI system lifecycle
  { id: 'A.9.2',   title: 'Information for users of AI systems',   description: 'Intended use, limitations, and risks communicated to users and interested parties.' },
  { id: 'A.9.3',   title: 'AI system design and development', detectable: false,      description: 'Lifecycle objectives, processes, and acceptance criteria defined and followed.' },
  { id: 'A.9.4',   title: 'AI system verification and validation', description: 'Verification and validation against acceptance criteria before deployment.' },
  { id: 'A.9.5',   title: 'AI system operation and monitoring',    description: 'Deployed AI systems operated per policy and monitored for drift, misuse, and incidents.' },
  // A.10 — Data for AI systems
  { id: 'A.10.2',  title: 'Allocation of responsibilities',        description: 'Responsibilities for AI systems distributed among suppliers, customers, and partners.' },
  { id: 'A.10.3',  title: 'Suppliers',                             description: 'AI-relevant supplier relationships governed by defined requirements and controls.' },
  { id: 'A.10.4',  title: 'Data provenance and preparation',       description: 'Origin, transformation, and preparation of AI data is recorded and controlled.' },
  // A.11 — Information for interested parties
  { id: 'A.11.2',  title: 'Reporting concerns', detectable: false,                    description: 'Concerns about AI system impacts can be raised, reviewed, and resolved.' },
  { id: 'A.11.5',  title: 'Communication of incidents',            description: 'AI incidents communicated to relevant interested parties, including authorities where required.' },
  // A.12 — Use of AI systems
  { id: 'A.12.4',  title: 'Human oversight of AI use',             description: 'Appropriate human oversight applied to AI use to limit unintended consequences.' },
  // A.13 — Third-party and customer relationships
  { id: 'A.13.2',  title: 'Third-party AI supply',                 description: 'Third-party AI components and services assessed before adoption and monitored thereafter.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const cwe = finding.cwe || '';
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();
  const text = rule + title;

  // A.5 — policy / governance
  if (cat === 'agentic' || /policy|governance|\.cursorrules|CLAUDE\.md|agent.?config/.test(text)) ids.add('A.5.2');
  if (/no.?policy|missing.?policy/.test(text)) ids.add('A.5.5');

  // A.6 — organization, impact, privacy/security by design
  if (/poison|rag\b|retrieval|embedding|memory/.test(text)) {
    ids.add('A.7.4'); ids.add('A.6.2.4');
  }
  if (cat === 'secrets' || cwe === 'CWE-200' || cwe === 'CWE-312' || cwe === 'CWE-798'
      || owasp === 'ASI06' || /prompt.?inject|jailbreak/.test(text) || owasp === 'ASI01') {
    ids.add('A.6.2.6');
  }
  if (/permission|role|segregation|least.?privilege/.test(text)) ids.add('A.6.1.2');

  // A.7 — resources, data quality, documentation
  if (cat === 'llm' || /inference|compute|gpu/.test(text)) ids.add('A.7.2');
  if (/no.?model.?card|missing.?documentation/.test(text)) ids.add('A.7.6');

  // A.8 — tooling
  if (/mcp|tool.?poison|tool.?registry/.test(text) || cat === 'config') ids.add('A.8.4');
  if (cat === 'llm') ids.add('A.8.2');

  // A.9 — lifecycle: info to users, verification, monitoring
  if (owasp === 'ASI08' || /human.?oversight|missing.?confirmation|auto.?accept|yolo/.test(text)) { ids.add('A.9.2'); ids.add('A.12.4'); }
  if (/no.?verification|no.?validation|unverified/.test(text)) ids.add('A.9.4');
  if (/no.?monitoring|no.?logging|telemetry|no.?observability/.test(text)) ids.add('A.9.5');

  // A.10/A.13 — supply chain, third parties
  if (cat === 'supply-chain' || cat === 'deps' || owasp === 'ASI04') {
    ids.add('A.10.3'); ids.add('A.10.2'); ids.add('A.13.2');
  }
  if (/provenance|signature|hash|attestation/.test(text)) ids.add('A.10.4');

  // A.11 — incident communication
  if (/incident|report/.test(text) && cat !== 'secrets') ids.add('A.11.5');

  return [...ids];
}
