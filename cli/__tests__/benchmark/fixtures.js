/**
 * Praxis Benchmark Ground-Truth Fixtures
 * =====================================
 *
 * Ground-truth testbed for measuring precision, recall, and false-positive rates
 * across vulnerability classes and AI security domains.
 */

export const GROUND_TRUTH_FIXTURES = [
  // ── True Positives (Vulnerable code — scanner MUST flag) ────────────────────
  {
    id: 'TP-SQLI-01',
    category: 'injection',
    expectedVulnerable: true,
    rule: 'SQL_INJECTION_TEMPLATE_LITERAL',
    language: 'javascript',
    code: `
function getUser(req, res) {
  const userId = req.query.id;
  const sql = \`SELECT * FROM users WHERE id = \${userId}\`;
  db.query(sql);
}
`,
  },
  {
    id: 'TP-CMD-01',
    category: 'injection',
    expectedVulnerable: true,
    rule: 'CMD_INJECTION_EXEC_TEMPLATE',
    language: 'javascript',
    code: `
import { exec } from 'child_process';
function pingHost(req, res) {
  const host = req.body.host;
  exec(\`ping -c 1 \${host}\`);
}
`,
  },
  {
    id: 'TP-PICKLE-01',
    category: 'deserialization',
    expectedVulnerable: true,
    rule: 'UNSAFE_DESERIALIZE_PICKLE',
    language: 'python',
    code: `
import pickle
def load_data(user_payload):
    data = pickle.loads(user_payload)
    return data
`,
  },
  {
    id: 'TP-RAG-01',
    category: 'llm',
    expectedVulnerable: true,
    rule: 'RAG_UNSANITIZED_INGESTION',
    language: 'javascript',
    code: `
async function ingest(req) {
  const userDocs = req.body.documents;
  await vectorStore.addDocuments(userDocs);
}
`,
  },

  // ── True Negatives (Benign / Protected code — scanner MUST NOT flag as high-confidence FP) ─
  {
    id: 'TN-SQLI-PARAM-01',
    category: 'injection',
    expectedVulnerable: false,
    rule: 'SQL_INJECTION_TEMPLATE_LITERAL',
    language: 'javascript',
    code: `
function getUserSafe(req, res) {
  const userId = parseInt(req.query.id, 10);
  const sql = "SELECT * FROM users WHERE id = $1";
  db.query(sql, [userId]);
}
`,
  },
  {
    id: 'TN-CMD-SAFE-01',
    category: 'injection',
    expectedVulnerable: false,
    rule: 'CMD_INJECTION_EXEC_TEMPLATE',
    language: 'javascript',
    code: `
import { execFile } from 'child_process';
function pingSafe(req, res) {
  const host = String(req.body.host).replace(/[^a-zA-Z0-9.-]/g, '');
  execFile('ping', ['-c', '1', host]);
}
`,
  },
  {
    id: 'TN-SQLI-COMMENT-01',
    category: 'injection',
    expectedVulnerable: false,
    rule: 'SQL_INJECTION_TEMPLATE_LITERAL',
    language: 'javascript',
    code: `
// Example usage:
// const query = \`SELECT * FROM users WHERE id = \${userId}\`;
const safeQuery = 'SELECT * FROM users';
`,
  },
  {
    id: 'TN-GUARDRAIL-AI-01',
    category: 'llm',
    expectedVulnerable: false,
    rule: 'PROMPT_INJECTION_DIRECT',
    language: 'python',
    code: `
from nemoguardrails import LLMRails, RailsConfig
rails = LLMRails(RailsConfig.from_path("./config"))
def query_ai(user_prompt):
    return rails.generate(messages=[{"role": "user", "content": user_prompt}])
`,
  },
  {
    id: 'TN-STATIC-CONST-01',
    category: 'injection',
    expectedVulnerable: false,
    rule: 'CMD_INJECTION_EXEC_TEMPLATE',
    language: 'javascript',
    code: `
import { exec } from 'child_process';
const FIXED_BACKUP_CMD = "tar -czf backup.tar.gz /var/data";
exec(FIXED_BACKUP_CMD);
`,
  },
];

export default GROUND_TRUTH_FIXTURES;
