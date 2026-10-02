/**
 * SARIF v2.1.0 output formatter.
 *
 * Centralizes the SARIF emission logic that previously lived in
 * `cli/commands/audit.js` and a separate copy in `cli/commands/ci.js`.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

const SARIF_VERSION = '2.1.0';

/**
 * Severity → SARIF `level` + GitHub `security-severity`.
 *
 * These are two different axes and both are needed:
 *   - `level` is the coarse SARIF gate (`error` / `warning` / `note`).
 *   - `security-severity` is the 0.0-10.0 number GitHub Code Scanning uses to rank,
 *     colour and filter alerts.
 *
 * Emitting `level` alone collapsed critical and high into the same bucket, so every
 * Code Scanning consumer saw compressed severity — the tiering the product is built on
 * was invisible exactly where people look for it. Both fields come from this one table
 * so they cannot drift apart.
 *
 * Emitted as a string because that is the form GitHub's own documentation uses.
 */
const SEVERITY = {
  critical: { level: 'error', securitySeverity: '9.5' },
  high: { level: 'error', securitySeverity: '7.5' },
  medium: { level: 'warning', securitySeverity: '5.0' },
  low: { level: 'note', securitySeverity: '2.5' },
  info: { level: 'note', securitySeverity: '0.0' },
};

/** Unknown or absent severity must not silently read as low-risk. */
const DEFAULT_SEVERITY = { level: 'warning', securitySeverity: '5.0' };

const forSeverity = (severity) => SEVERITY[severity] || DEFAULT_SEVERITY;

export default function sarif(report, options = {}) {
  const {
    toolName = 'praxis',
    toolVersion = report.version || '1.0.0',
    informationUri = 'https://github.com/Ganron007/Praxis',
  } = options;

  const findings = report.findings || [];
  const rules = collectRules(findings);

  const sarifReport = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version: toolVersion,
            informationUri,
            rules,
          },
        },
        results: findings.map(toResult),
      },
    ],
  };

  return JSON.stringify(sarifReport, null, 2);
}

function collectRules(findings) {
  const seen = new Map();
  for (const f of findings) {
    const id = f.ruleId || f.pattern || f.type || 'finding';
    if (seen.has(id)) continue;
    // Collect tags for the rule definition so GitHub Security tab groups
    // Praxis findings by AI/LLM/MCP/supply-chain categories.
    const ruleTags = ['praxis'];
    if (f.category) ruleTags.push(f.category);
    if (f.owasp) ruleTags.push(f.owasp);
    if (f.standards) {
      for (const [, ids] of Object.entries(f.standards)) {
        for (const sid of ids) ruleTags.push(sid);
      }
    }
    const sev = forSeverity(f.severity);
    seen.set(id, {
      id,
      name: f.patternName || id,
      shortDescription: { text: f.patternName || id },
      fullDescription: { text: f.description || f.patternName || id },
      defaultConfiguration: {
        level: sev.level,
      },
      properties: {
        tags: [...new Set(ruleTags)], // dedup
        // GitHub Code Scanning ranks and filters on this numeric property.
        'security-severity': sev.securitySeverity,
      },
    });
  }
  return [...seen.values()];
}

function toResult(f) {
  const normFile = String(f.file || f.path || '')
    .replace(/\\/g, '/')
    .replace(/^[a-zA-Z]:\/+/, '')
    .replace(/^.*\/Praxis\/showcase-target\//, 'showcase-target/')
    .replace(/^.*\/Praxis\//, '');

  const sev = forSeverity(f.severity);

  const result = {
    ruleId: f.ruleId || f.pattern || f.type || 'finding',
    level: sev.level,
    message: { text: f.description || f.message || f.patternName || 'finding' },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: normFile },
          region: {
            startLine: f.line || 1,
            startColumn: f.column || 1,
          },
        },
      },
    ],
  };

  // Embed AI-security standard tags so SARIF consumers (GitHub Code Scanning,
  // SonarQube, etc.) can filter / display alignment per finding.
  const props = { 'security-severity': sev.securitySeverity };
  if (f.cwe) props.cwe = f.cwe;
  if (f.owasp) props.owasp = f.owasp;
  if (f.standards && Object.keys(f.standards).length > 0) {
    props.standards = f.standards;
    const tags = [];
    for (const [, ids] of Object.entries(f.standards)) {
      for (const id of ids) tags.push(id);
    }
    if (tags.length > 0) props.tags = tags;
  }
  result.properties = props;

  return result;
}
