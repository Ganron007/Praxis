import { getStandardsSummary } from '../../utils/standards/index.js';

export default function renderComplianceReport(report, options = {}) {
  const findings = report.findings || [];
  const summary = getStandardsSummary(findings);

  // Focus on OWASP LLM and NIST AI 600-1
  const owasp = summary['owasp-llm'];
  const nist = summary['nist-ai-600-1'];

  const lines = [];
  lines.push('================================================================================');
  lines.push('                      PRAXIS GRC COMPLIANCE AUDIT REPORT');
  lines.push('================================================================================');
  lines.push(`Scanned At:     ${report.scannedAt || new Date().toISOString()}`);
  lines.push(`Total Findings: ${findings.length}`);
  lines.push(`Security Score: ${report.score || 100}/100 (Grade: ${report.grade || 'A'})`);
  lines.push('');

  lines.push('--------------------------------------------------------------------------------');
  lines.push(' STANDARDS COVERAGE SUMMARY');
  lines.push('--------------------------------------------------------------------------------');
  if (owasp) {
    lines.push(`  * ${owasp.title} (v${owasp.version}):`);
    lines.push(`    - Controls Flagged: ${owasp.flaggedControls} of ${owasp.totalControls} (${owasp.coverage})`);
  }
  if (nist) {
    lines.push(`  * ${nist.title} (v${nist.version}):`);
    lines.push(`    - Controls Flagged: ${nist.flaggedControls} of ${nist.totalControls} (${nist.coverage})`);
  }
  lines.push('');

  lines.push('--------------------------------------------------------------------------------');
  lines.push(' DETAILED CONTROL MAPPINGS');
  lines.push('--------------------------------------------------------------------------------');

  const renderDetailedStandard = (std) => {
    if (!std) return;
    lines.push(`### Standard: ${std.title} (v${std.version})`);
    lines.push(`URL: ${std.url}`);
    lines.push('');
    const flagged = (std.controls || []).filter(c => c.findingCount > 0);
    if (flagged.length === 0) {
      lines.push('  ✔ All controls in this standard are compliant (no findings).');
      lines.push('');
      return;
    }

    for (const ctrl of flagged) {
      lines.push(`  [NON-COMPLIANT] Control ${ctrl.id}: ${ctrl.title}`);
      if (ctrl.description) {
        lines.push(`    Description: ${ctrl.description}`);
      }
      lines.push(`    Flagged Occurrences: ${ctrl.findingCount}`);
      lines.push('');
      
      // List matching findings
      const matchingFindings = findings.filter(f => {
        const stdMap = f.standards || {};
        const ctrlIds = stdMap[std.name] || [];
        return ctrlIds.includes(ctrl.id);
      });

      for (const f of matchingFindings) {
        lines.push(`      - [${f.severity.toUpperCase()}] ${f.file}${f.line ? ` (line ${f.line})` : ''}`);
        lines.push(`        Finding: ${f.title}`);
        lines.push(`        Remediation: ${f.remediation || 'Refer to Praxis guidelines'}`);
      }
      lines.push('');
    }
  };

  if (owasp) renderDetailedStandard(owasp);
  if (nist) renderDetailedStandard(nist);

  lines.push('================================================================================');
  lines.push('                              GRC RECOMMENDATIONS');
  lines.push('================================================================================');
  if (findings.length === 0) {
    lines.push('  1. Maintain current posture by scheduling regular automated scans.');
    lines.push('  2. Enable real-time commit hooks to prevent future secret exposure.');
  } else {
    lines.push('  1. Prioritize critical and high severity findings matching OWASP LLM01/LLM02.');
    lines.push('  2. Implement runtime guardrails to satisfy NIST AI 600-1 inputs/outputs mapping.');
    lines.push('  3. Remediate flagged findings before promoting code to production environments.');
  }
  lines.push('================================================================================');

  return lines.join('\n');
}
