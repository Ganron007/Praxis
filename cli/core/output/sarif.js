/**
 * SARIF v2.1.0 output formatter.
 *
 * Centralizes the SARIF emission logic that previously lived in
 * `cli/commands/audit.js` and a separate copy in `cli/commands/ci.js`.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

const SARIF_VERSION = '2.1.0';

const LEVEL_FROM_SEVERITY = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

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
    seen.set(id, {
      id,
      name: f.patternName || id,
      shortDescription: { text: f.patternName || id },
      fullDescription: { text: f.description || f.patternName || id },
      defaultConfiguration: {
        level: LEVEL_FROM_SEVERITY[f.severity] || 'warning',
      },
      properties: {
        tags: [...new Set(ruleTags)], // dedup
      },
    });
  }
  return [...seen.values()];
}

function toResult(f) {
  const result = {
    ruleId: f.ruleId || f.pattern || f.type || 'finding',
    level: LEVEL_FROM_SEVERITY[f.severity] || 'warning',
    message: { text: f.description || f.message || f.patternName || 'finding' },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file || f.path || '' },
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
  const props = {};
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
  if (Object.keys(props).length > 0) result.properties = props;

  return result;
}
