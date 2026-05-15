/**
 * OWASP Machine Learning Security Top 10.
 * https://owasp.org/www-project-machine-learning-security-top-10/
 *
 * Covers classical ML model attacks (separate from the LLM Top 10).
 */

export const name = 'owasp-ml';
export const version = '2023';
export const title = 'OWASP Machine Learning Security Top 10';
export const description = 'Top risks specific to machine learning systems.';
export const url = 'https://owasp.org/www-project-machine-learning-security-top-10/';

export const controls = [
  { id: 'ML01', title: 'Input Manipulation Attack',  description: 'Adversarial inputs cause incorrect predictions.' },
  { id: 'ML02', title: 'Data Poisoning Attack',      description: 'Tainted training data biases or backdoors model.' },
  { id: 'ML03', title: 'Model Inversion Attack',     description: 'Reconstruct training data from model outputs.' },
  { id: 'ML04', title: 'Membership Inference Attack', description: 'Determine if a record was in the training set.' },
  { id: 'ML05', title: 'Model Theft',                description: 'Steal model weights via API or filesystem access.' },
  { id: 'ML06', title: 'AI Supply Chain Attacks',    description: 'Compromised pretrained models or libraries.' },
  { id: 'ML07', title: 'Transfer Learning Attack',   description: 'Backdoors propagated from upstream pretrained model.' },
  { id: 'ML08', title: 'Model Skewing',              description: 'Feedback loops bias online models.' },
  { id: 'ML09', title: 'Output Integrity Attack',    description: 'Tamper with model outputs in transit.' },
  { id: 'ML10', title: 'Model Poisoning',            description: 'Malicious modifications to model parameters.' },
];

export function mapFinding(finding) {
  const ids = new Set();
  const owasp = finding.owasp || '';
  const cat = finding.category || '';
  const rule = (finding.rule || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();

  if (/adversarial|prompt.?inject|jailbreak/.test(rule + title) || owasp === 'ASI01') ids.add('ML01');
  if (cat === 'memory-poisoning' || cat === 'rag' || owasp === 'ASI05') { ids.add('ML02'); ids.add('ML10'); }
  if (/inversion|extract.?training/.test(rule + title)) ids.add('ML03');
  if (/membership.?inference/.test(rule + title)) ids.add('ML04');
  if (/model.?(?:theft|steal|exfil)|weights.?leak/.test(rule + title)) ids.add('ML05');
  if (cat === 'supply-chain' || cat === 'deps' || owasp === 'ASI04') ids.add('ML06');
  if (/pretrain|fine.?tune.?backdoor|transfer.?learn/.test(rule + title)) ids.add('ML07');
  if (/feedback.?loop|skew/.test(rule + title)) ids.add('ML08');
  if (/output.?integrity|response.?tamper/.test(rule + title)) ids.add('ML09');

  return [...ids];
}
