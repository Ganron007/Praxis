/**
 * HTML Report Generator
 * ======================
 *
 * Generates a standalone interactive HTML security report.
 * No external dependencies — everything inline.
 *
 * Features:
 *   - Severity filter toolbar (toggle critical/high/medium/low)
 *   - Category bar chart (deductions visualization)
 *   - Collapsible finding rows with code context
 *   - Click-to-copy praxis-ignore annotations
 *   - Text search across findings
 *   - Print-friendly styles
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getComplianceSummary } from '../utils/compliance-map.js';
import { getStandardsSummary } from '../utils/standards/index.js';
import { FALLBACK_CATEGORY_MAP, CATEGORIES } from './scoring-engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch {
    return '1.0.0';
  }
})();

function resolveBucket(category) {
  if (CATEGORIES[category]) return category;
  if (FALLBACK_CATEGORY_MAP[category] !== undefined) return FALLBACK_CATEGORY_MAP[category];
  return 'injection';
}

function renderStandardsAlignment(findings, escFn) {
  let summary;
  try { summary = getStandardsSummary(findings); } catch { summary = null; }
  if (!summary) return '';

  const cards = Object.values(summary).map(std => {
    const pct = std.totalControls > 0 ? Math.round((std.flaggedControls / std.totalControls) * 100) : 0;
    const color = std.flaggedControls > 0 ? (pct >= 50 ? '#ef4444' : '#f97316') : '#22c55e';
    const ctrls = std.controls.map(c => {
      const cls = c.findingCount > 0 ? 'sev sev-high' : 'sev sev-low';
      return `<span class="${cls}" title="${escFn(c.title)}" style="margin:2px;display:inline-block">${escFn(c.id)}${c.findingCount ? ' (' + c.findingCount + ')' : ''}</span>`;
    }).join(' ');
    return `<div class="summary-card">
      <h3>${escFn(std.title)} <small style="color:#64748b">v${escFn(std.version)}</small></h3>
      <div class="big" style="color:${color}">${std.coverage}</div>
      <small>controls flagged</small>
      <div style="margin-top:0.75rem;line-height:1.8">${ctrls}</div>
    </div>`;
  }).join('\n');

  return `<div class="summary-grid" style="grid-template-columns:repeat(2,1fr)">${cards}</div>`;
}

export class HTMLReporter {
  /**
   * Generate an HTML report from scan results.
   */
  generate(scoreResult, findings, recon, rootPath) {
    const projectName = path.basename(rootPath);
    const date = new Date().toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });

    const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#ef4444', F: '#dc2626' };
    const sevColors = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

    const categoryRows = Object.entries(scoreResult.categories)
      .map(([key, cat]) => {
        const count = Object.values(cat.counts).reduce((a, b) => a + b, 0);
        return `<tr>
          <td>${cat.label}</td>
          <td>${count}</td>
          <td style="color:${cat.deduction > 0 ? '#ef4444' : '#22c55e'}">${cat.deduction > 0 ? '-' + cat.deduction : '0'}</td>
        </tr>`;
      }).join('\n');

    const findingRows = findings.slice(0, 200).map(f => {
      const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
      return `<tr>
        <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
        <td><code>${relFile}:${f.line}</code></td>
        <td><strong>${f.title || f.rule}</strong><br><small>${f.description?.slice(0, 120) || ''}</small></td>
        <td><code>${(f.matched || '').slice(0, 60)}</code></td>
        <td>${f.fix ? `<small>${f.fix.slice(0, 100)}</small>` : ''}</td>
      </tr>`;
    }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Praxis Security Report — ${projectName}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
.container{max-width:1200px;margin:0 auto}
h1{font-size:2rem;margin-bottom:0.5rem;color:#38bdf8}
h2{font-size:1.3rem;margin:2rem 0 1rem;color:#94a3b8;border-bottom:1px solid #1e293b;padding-bottom:0.5rem}
.meta{color:#64748b;margin-bottom:2rem}
.score-card{display:flex;align-items:center;gap:2rem;background:#1e293b;padding:2rem;border-radius:12px;margin-bottom:2rem}
.score-number{font-size:4rem;font-weight:bold}
.grade{font-size:3rem;font-weight:bold;width:80px;height:80px;display:flex;align-items:center;justify-content:center;border-radius:12px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.stat{background:#1e293b;padding:1.5rem;border-radius:8px;text-align:center}
.stat-number{font-size:2rem;font-weight:bold}
.stat-label{color:#64748b;font-size:0.85rem}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;margin-bottom:2rem}
th{background:#334155;text-align:left;padding:0.75rem 1rem;font-size:0.8rem;text-transform:uppercase;color:#94a3b8}
td{padding:0.75rem 1rem;border-top:1px solid #1e293b;font-size:0.85rem;vertical-align:top}
tr:hover{background:#334155}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.8rem;color:#38bdf8}
small{color:#64748b}
.sev{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:bold;text-transform:uppercase}
.sev-critical{background:#dc262633;color:#fca5a5}
.sev-high{background:#f9731633;color:#fdba74}
.sev-medium{background:#eab30833;color:#fde047}
.sev-low{background:#3b82f633;color:#93c5fd}
.footer{text-align:center;color:#475569;margin-top:3rem;padding:2rem;border-top:1px solid #1e293b}
</style>
</head>
<body>
<div class="container">
  <h1>Praxis Security Report</h1>
  <p class="meta">${projectName} — ${date}</p>

  <div class="score-card">
    <div class="grade" style="background:${gradeColors[scoreResult.grade.letter]}22;color:${gradeColors[scoreResult.grade.letter]}">${scoreResult.grade.letter}</div>
    <div>
      <div class="score-number" style="color:${gradeColors[scoreResult.grade.letter]}">${scoreResult.score}/100</div>
      <div style="color:#94a3b8">${scoreResult.grade.label}</div>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-number" style="color:${sevColors.critical}">${bySeverity.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-number" style="color:${sevColors.high}">${bySeverity.high}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-number" style="color:${sevColors.medium}">${bySeverity.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-number" style="color:${sevColors.low}">${bySeverity.low}</div><div class="stat-label">Low</div></div>
  </div>

  <h2>Category Breakdown</h2>
  <table>
    <thead><tr><th>Category</th><th>Findings</th><th>Deduction</th></tr></thead>
    <tbody>${categoryRows}</tbody>
  </table>

  <h2>Findings (${findings.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Code</th><th>Fix</th></tr></thead>
    <tbody>${findingRows || '<tr><td colspan="5" style="text-align:center;color:#22c55e">No findings — clean!</td></tr>'}</tbody>
  </table>

  <h2>Compliance Mapping</h2>
  ${(() => {
    const compliance = getComplianceSummary(findings);
    const s = compliance.summary;
    return `<div class="stats">
      <div class="stat"><div class="stat-number" style="color:#38bdf8">${s.soc2Controls}</div><div class="stat-label">SOC 2 Controls</div></div>
      <div class="stat"><div class="stat-number" style="color:#38bdf8">${s.iso27001Controls}</div><div class="stat-label">ISO 27001 Controls</div></div>
      <div class="stat"><div class="stat-number" style="color:#38bdf8">${s.nistAiRmfControls}</div><div class="stat-label">NIST AI RMF Controls</div></div>
      <div class="stat"><div class="stat-number" style="color:#94a3b8">${s.totalFindings}</div><div class="stat-label">Mapped Findings</div></div>
    </div>
    <table>
      <thead><tr><th>Framework</th><th>Controls Impacted</th><th>Details</th></tr></thead>
      <tbody>
        <tr><td>SOC 2 Type II</td><td>${s.soc2Controls}</td><td>${Object.entries(compliance.soc2).map(([k,v]) => k + ' (' + v + ')').join(', ') || 'None'}</td></tr>
        <tr><td>ISO 27001:2022</td><td>${s.iso27001Controls}</td><td>${Object.entries(compliance.iso27001).map(([k,v]) => k + ' (' + v + ')').join(', ') || 'None'}</td></tr>
        <tr><td>NIST AI RMF</td><td>${s.nistAiRmfControls}</td><td>${Object.entries(compliance.nistAiRmf).map(([k,v]) => k + ' (' + v + ')').join(', ') || 'None'}</td></tr>
      </tbody>
    </table>`;
  })()}

  <h2>AI Security Standards Alignment</h2>
  ${renderStandardsAlignment(findings, (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'))}

  ${recon ? `<h2>Attack Surface</h2>
  <table>
    <tbody>
      <tr><td>Frameworks</td><td>${(recon.frameworks || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Languages</td><td>${(recon.languages || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Databases</td><td>${(recon.databases || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Cloud Providers</td><td>${(recon.cloudProviders || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Auth Patterns</td><td>${(recon.authPatterns || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>CI/CD</td><td>${(recon.cicd || []).map(c => c.platform).join(', ') || 'None detected'}</td></tr>
      <tr><td>API Routes</td><td>${(recon.apiRoutes || []).length} discovered</td></tr>
    </tbody>
  </table>` : ''}

  <div class="footer">
    Generated by <strong>Praxis</strong> — From finding to fix, on autopilot.
  </div>
</div>
</body>
</html>`;
  }

  /**
   * Generate and write HTML report to file.
   */
  generateToFile(scoreResult, findings, recon, rootPath, outputPath) {
    const html = this.generate(scoreResult, findings, recon, rootPath);
    fs.writeFileSync(outputPath, html);
    return outputPath;
  }

  /**
   * Generate a full interactive audit report including deps and remediation plan.
   *
   * Interactive features:
   *   - Severity filter toolbar
   *   - Category deduction bar chart
   *   - Collapsible finding rows with code context
   *   - Click-to-copy praxis-ignore annotations
   *   - Text search across findings
   */
  generateFullReport(scoreResult, findings, depVulns, recon, remediationPlan, rootPath, outputPath) {
    const projectName = path.basename(rootPath);
    const date = new Date().toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });

    const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#ef4444', F: '#dc2626' };
    const sevColors = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

    // Category chart data
    const catEntries = Object.entries(scoreResult.categories);
    const maxDeduction = Math.max(...catEntries.map(([, c]) => c.deduction), 1);
    const categoryBars = catEntries.map(([key, cat]) => {
      const count = Object.values(cat.counts).reduce((a, b) => a + b, 0);
      const pct = Math.round((cat.deduction / maxDeduction) * 100);
      const color = cat.deduction > 5 ? '#ef4444' : cat.deduction > 0 ? '#f97316' : '#22c55e';
      return `<div class="bar-row">
        <span class="bar-label">${this.esc(cat.label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
        <span class="bar-value" style="color:${color}">${cat.deduction > 0 ? '-' + Math.round(cat.deduction * 10) / 10 : '0'} pts</span>
        <span class="bar-count">${count} findings</span>
      </div>`;
    }).join('\n');

    // Finding rows with collapsible detail
    const fileCache = new Map();
    const codeContextFor = (f) => {
      if (f.codeContext && f.codeContext.length > 0) return f.codeContext;
      if (!f.file || !f.line) return [];
      let abs = f.file;
      if (!path.isAbsolute(abs)) abs = path.join(rootPath, f.file);
      let content = fileCache.get(abs);
      if (content === undefined) {
        try { content = fs.readFileSync(abs, 'utf-8'); } catch { content = null; }
        fileCache.set(abs, content);
      }
      if (!content) return [];
      const lines = content.split('\n');
      const start = Math.max(0, f.line - 4);
      const end = Math.min(lines.length, f.line + 2);
      return lines.slice(start, end).map((text, idx) => ({
        line: start + idx + 1,
        text,
        highlight: start + idx + 1 === f.line,
      }));
    };
    const findingRows = findings.slice(0, 500).map((f, i) => {
      const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
      const ctx = codeContextFor(f);
      let codeBlock = '';
      if (ctx.length > 0) {
        const codeLines = ctx.map(c =>
          `<span style="${c.highlight ? 'background:#dc262633;display:block;' : ''}">${String(c.line).padStart(4)} ${this.esc(c.text)}</span>`
        ).join('');
        codeBlock = `<pre class="code-block"><code>${codeLines}</code></pre>`;
      }
      const ignoreAnnotation = `praxis-ignore ${f.rule || ''}`.trim();

      // LLM deep-analysis verdict badge + reasoning (--deep runs)
      const deepColors = { confirmed: '#dc2626', likely: '#f97316', unlikely: '#3b82f6', false_positive: '#22c55e' };
      const deepBadge = f.deepAnalysis
        ? `<span class="deep-badge" style="background:${deepColors[f.deepAnalysis.exploitability] || '#64748b'}">LLM ${f.deepAnalysis.exploitability.replace('_', ' ')}</span>`
        : '';
      const deepBlock = f.deepAnalysis
        ? `<p class="finding-deep"><strong>Deep analysis (LLM):</strong> tainted=${f.deepAnalysis.tainted}, sanitized=${f.deepAnalysis.sanitized}<br>${this.esc(f.deepAnalysis.reasoning || '')}${f.deepAnalysis.attackVector ? `<br><strong>Attack vector:</strong> ${this.esc(f.deepAnalysis.attackVector)}` : ''}${f.deepAnalysis.fix ? `<br><strong>LLM fix:</strong> ${this.esc(f.deepAnalysis.fix)}` : ''}</p>`
        : '';
      // Confidence chip — low/medium confidence signals possible false positives
      const confChip = f.confidence && f.confidence !== 'high'
        ? `<span class="conf-chip conf-${f.confidence}">${f.confidence} confidence</span>`
        : '';
      const eaaChip = f.eaa
        ? `<span class="eaa-chip" title="Endpoint AI Agent Abuse technique ${this.esc(f.eaa)}">${this.esc(f.eaa)}</span>`
        : '';

      return `<tr class="finding-row" data-sev="${f.severity}" data-rule="${this.esc(f.rule || '')}" data-text="${this.esc((f.title || '') + ' ' + (f.description || '') + ' ' + relFile).toLowerCase()}">
        <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
        <td><code>${this.esc(relFile)}:${f.line}</code></td>
        <td>
          <strong class="finding-title" onclick="toggleDetail(${i})">${this.esc(f.title || f.rule)}</strong>
          ${confChip}${deepBadge}${eaaChip}
          <div id="detail-${i}" class="finding-detail" style="display:none">
            <p>${this.esc((f.description || '').slice(0, 300))}</p>
            ${f.cwe ? `<p class="finding-meta">CWE: ${this.esc(f.cwe)}${f.owasp ? ` | OWASP: ${this.esc(f.owasp)}` : ''}</p>` : ''}
            ${codeBlock}
            ${deepBlock}
            ${f.fix ? `<p class="finding-fix">Fix: ${this.esc(f.fix.slice(0, 200))}</p>` : ''}
            <button class="copy-btn" onclick="copyIgnore('${this.esc(ignoreAnnotation)}',this);event.stopPropagation()">Copy ignore annotation</button>
          </div>
        </td>
        <td><code>${this.esc((f.matched || '').slice(0, 60))}</code></td>
        <td>${f.fix ? `<small>${this.esc(f.fix.slice(0, 100))}</small>` : ''}</td>
      </tr>`;
    }).join('\n');

    // Dep vuln rows
    const depRows = (depVulns || []).slice(0, 100).map(d => {
      const sev = d.severity === 'moderate' ? 'medium' : d.severity;
      return `<tr>
        <td><span class="sev sev-${sev}">${(d.severity || 'unknown').toUpperCase()}</span></td>
        <td><code>${this.esc(d.package || d.id || 'unknown')}</code></td>
        <td>${this.esc((d.description || '').slice(0, 150))}</td>
      </tr>`;
    }).join('\n');

    // Remediation plan rows
    const sevIcons = { critical: '&#x1F534;', high: '&#x1F7E0;', medium: '&#x1F7E1;', low: '&#x1F535;' };
    let currentSev = null;
    let planHTML = '';
    for (const item of (remediationPlan || []).slice(0, 100)) {
      if (item.severity !== currentSev) {
        currentSev = item.severity;
        const label = { critical: 'CRITICAL — fix immediately', high: 'HIGH — fix before deploy', medium: 'MEDIUM — fix soon', low: 'LOW — review when possible' };
        planHTML += `<tr class="sev-header"><td colspan="5" style="background:#1e293b;padding:1rem;font-weight:bold;color:${sevColors[currentSev] || '#94a3b8'}">${sevIcons[currentSev] || ''} ${label[currentSev] || currentSev.toUpperCase()}</td></tr>\n`;
      }
      planHTML += `<tr>
        <td>${item.priority}</td>
        <td><span class="sev sev-${item.severity}">${this.esc(item.categoryLabel)}</span></td>
        <td><strong>${this.esc(item.title)}</strong></td>
        <td><code>${this.esc(item.file)}</code></td>
        <td><small>${this.esc((item.action || '').slice(0, 120))}</small></td>
      </tr>\n`;
    }

    // ── AI attack-surface lanes (P-IMP-021) ────────────────────────────────
    const AI_LANES = [
      { id: 'mcp', label: 'MCP Servers & Tools', match: f => /^MCP_|MCP:/i.test(f.rule || '') || /MCP/i.test(f.title || '') },
      { id: 'agent-config', label: 'Agent Configs & Instructions', match: f => /AGENT_CFG|AGENT_CONFIG|MEMORY_POISON|HOOK/i.test(f.rule || '') },
      { id: 'prompt-injection', label: 'Prompt Injection & Jailbreaks', match: f => /PROMPT|JAILBREAK|PROBE|DAN/i.test(f.rule || '') },
      { id: 'model', label: 'Model Artifacts', match: f => /MODEL_FILE|PICKLE|SAFETENSOR/i.test(f.rule || '') },
      { id: 'rag', label: 'RAG & Vector Stores', match: f => /RAG|VECTOR|EMBEDDING/i.test(f.rule || '') },
      { id: 'agent-supply', label: 'Agent Supply Chain & Attestation', match: f => /ATTESTATION|AGENTIC_SUPPLY/i.test(f.rule || '') },
      { id: 'eaa', label: 'Local Agent Abuse (EAA)', match: f => Boolean(f.eaa) },
      { id: 'llm', label: 'Other AI / LLM Security', match: f => f.category === 'llm' || f.category === 'agentic' },
    ];
    const laneSections = AI_LANES.map(lane => {
      const hits = findings.filter(lane.match);
      if (hits.length === 0) return '';
      const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const h of hits) sevCounts[h.severity] = (sevCounts[h.severity] || 0) + 1;
      const sevLine = ['critical', 'high', 'medium', 'low']
        .filter(s => sevCounts[s] > 0)
        .map(s => `<span style="color:${sevColors[s]}">${sevCounts[s]} ${s}</span>`)
        .join(' · ');
      const top = hits.slice(0, 3).map(h => `<li>${this.esc(h.title || h.rule)}</li>`).join('');
      return `<div class="lane-card">
        <div class="lane-head"><strong>${lane.label}</strong><span class="lane-count">${hits.length} finding(s)</span></div>
        <div class="lane-sev">${sevLine}</div>
        ${top ? `<ul class="lane-top">${top}</ul>` : ''}
      </div>`;
    }).join('');
    const aiLaneHTML = laneSections
      ? `<div class="lane-grid">${laneSections}</div>`
      : '<p style="color:#22c55e;font-weight:bold">No AI attack-surface findings.</p>';

    // ── Standards coverage gap map (P-IMP-024, 3-state) ────────────────────
    const standardsGapHTML = (scoreResult.standardsSummary
      ? Object.entries(scoreResult.standardsSummary)
        .map(([stdName, std]) => {
          const flagged = (std.controls || []).filter(c => c.status === 'flagged');
          const toolGap = (std.controls || []).filter(c => c.status !== 'flagged' && c.detectable === false);
          const noEvidence = (std.controls || []).filter(c => c.status !== 'flagged' && c.detectable !== false);
          const flaggedLine = flagged.length > 0
            ? `<span class="cov cov-flagged">Flagged (${flagged.length}): ${flagged.map(c => this.esc(c.id)).join(', ')}</span>`
            : '<span class="cov cov-none">No controls flagged in this scan</span>';
          const noEvidenceLine = noEvidence.length > 0
            ? `<br><span class="cov cov-nodata">No evidence in this scan (${noEvidence.length}): ${noEvidence.map(c => this.esc(c.id)).join(', ')}</span>`
            : '';
          const toolGapLine = toolGap.length > 0
            ? `<br><span class="cov cov-gap">No detection rule (${toolGap.length}): ${toolGap.map(c => this.esc(c.id)).join(', ')}</span>`
            : '';
          return `<div class="std-gap-row"><strong>${this.esc(std.title || stdName)}</strong> — ${std.flaggedControls}/${std.totalControls} flagged<div style="font-size:0.75rem;margin-top:0.3rem">${flaggedLine}${noEvidenceLine}${toolGapLine}</div></div>`;
        }).join('')
      : '<p style="color:#94a3b8">Standards summary unavailable.</p>');

    // ── Security trend (P-IMP-025) ─────────────────────────────────────────
    let history = [];
    try {
      const historyFile = path.join(rootPath, '.praxis', 'history.json');
      if (fs.existsSync(historyFile)) {
        history = JSON.parse(fs.readFileSync(historyFile, 'utf-8'));
      }
    } catch { history = []; }
    const recent = Array.isArray(history) ? history.slice(-8) : [];
    const trendHTML = recent.length > 0
      ? `<table>
        <thead><tr><th>When</th><th>Score</th><th>Grade</th><th>Findings</th><th>Trend</th></tr></thead>
        <tbody>${recent.map((e, idx) => {
          const prev = idx > 0 ? recent[idx - 1].score : e.score;
          const delta = Math.round((e.score - prev) * 10) / 10;
          const arrow = delta > 0 ? '<span style="color:#22c55e">▲ improving</span>' : delta < 0 ? '<span style="color:#ef4444">▼ declining</span>' : '<span style="color:#64748b">— flat</span>';
          const barW = Math.max(4, Math.round(e.score));
          return `<tr>
            <td>${new Date(e.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</td>
            <td><div class="trend-bar" style="width:${barW}%;background:${gradeColors[e.grade] || '#64748b'}"></div> ${e.score}</td>
            <td>${this.esc(e.grade || '?')}</td>
            <td>${e.totalFindings ?? '—'}</td>
            <td>${idx === 0 ? '<span style="color:#64748b">baseline</span>' : arrow}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>`
      : '<p style="color:#94a3b8">No scan history yet — run more scans to see the trend.</p>';

    // ── Professional finding cards grouped by scoring category ─────────────
    const bucketEntries = catEntries.map(([key, cat]) => {
      const hits = findings.filter(f => resolveBucket(f.category) === key);
      return { key, label: cat.label, deduction: cat.deduction, hits };
    }).filter(b => b.hits.length > 0);

    const sevLabel = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
    const refsFor = (f) => {
      const parts = [];
      if (f.cwe) parts.push(`<a href="https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html" target="_blank" rel="noopener">${this.esc(f.cwe)}</a>`);
      if (f.owasp) parts.push(`<span>${this.esc(f.owasp)}</span>`);
      if (f.standards) {
        for (const [std, ids] of Object.entries(f.standards)) {
          if (ids.length > 0) parts.push(`<span>${this.esc(std)}: ${ids.map(i => this.esc(i)).join(', ')}</span>`);
        }
      }
      if (f.eaa) parts.push(`<span>EAA ${this.esc(f.eaa)}</span>`);
      return parts.length > 0 ? parts.join(' · ') : '';
    };

    let cardIdx = 0;
    const deepColors = { confirmed: '#dc2626', likely: '#f97316', unlikely: '#3b82f6', false_positive: '#22c55e' };
    const findingCards = (() => {
      let html2 = '';
      for (const bucket of bucketEntries) {
        html2 += `<section class="cat-section" id="cat-${bucket.key}" data-cat="${bucket.key}">
  <div class="cat-header">
    <h3>${this.esc(bucket.label)}</h3>
    <span class="cat-count">${bucket.hits.length} finding(s)${bucket.deduction > 0 ? ` · −${Math.round(bucket.deduction * 10) / 10} pts` : ''}</span>
  </div>`;
        for (const f of bucket.hits) {
          const idx = cardIdx++;
          const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
          const ctx = codeContextFor(f);
          const deepBadge = f.deepAnalysis
            ? `<span class="deep-badge" style="background:${deepColors[f.deepAnalysis.exploitability] || '#64748b'}">LLM ${f.deepAnalysis.exploitability.replace('_', ' ')}</span>`
            : '';
          const confChip = f.confidence && f.confidence !== 'high'
            ? `<span class="conf-chip conf-${f.confidence}">${f.confidence} confidence</span>`
            : '';
          const eaaChip = f.eaa
            ? `<span class="eaa-chip" title="Endpoint AI Agent Abuse technique ${this.esc(f.eaa)}">${this.esc(f.eaa)}</span>`
            : '';
          const evidence = ctx.length > 0
            ? `<pre class="code-block"><code>${ctx.map(c => `<span style="${c.highlight ? 'background:#dc262633;display:block;' : ''}">${String(c.line).padStart(4)} ${this.esc(c.text)}</span>`).join('')}</code></pre>`
            : `<p class="muted">No code excerpt available${f.matched ? ` — matched: <code>${this.esc(String(f.matched).slice(0, 120))}</code>` : ''}.</p>`;
          const deepBlock = f.deepAnalysis
            ? `<div class="deep-block"><strong>LLM deep analysis:</strong> ${this.esc(f.deepAnalysis.exploitability.replace('_', ' '))} — tainted=${f.deepAnalysis.tainted}, sanitized=${f.deepAnalysis.sanitized}<br>${this.esc(f.deepAnalysis.reasoning || '')}${f.deepAnalysis.fix ? `<br><strong>Suggested fix:</strong> ${this.esc(f.deepAnalysis.fix)}` : ''}</div>`
            : '';
          const refs = refsFor(f);
          const ignoreAnnotation = `praxis-ignore ${f.rule || ''}`.trim();
          html2 += `<article class="finding-card" data-sev="${f.severity}" data-text="${this.esc((f.title || '') + ' ' + (f.description || '') + ' ' + relFile).toLowerCase()}">
    <header class="card-head" onclick="toggleCard(${idx})">
      <span class="sev sev-${f.severity}">${sevLabel[f.severity] || f.severity.toUpperCase()}</span>
      <div class="card-title"><strong>${this.esc(f.title || f.rule)}</strong><br><code class="card-loc">${this.esc(relFile)}:${f.line || 0}</code></div>
      <div class="card-chips">${confChip}${deepBadge}${eaaChip}</div>
    </header>
    <div class="card-body" id="card-${idx}" style="display:none">
      <h4>What this means</h4>
      <p>${this.esc(f.description || 'No description provided.')}</p>
      ${deepBlock}
      <h4>Evidence</h4>
      ${evidence}
      <h4>How to fix</h4>
      <p class="fix-text">${this.esc((f.fix || 'Review the flagged location and apply the applicable mitigation for this rule.').slice(0, 400))}</p>
      ${refs ? `<h4>References</h4><p class="refs">${refs}</p>` : ''}
      <button class="copy-btn" onclick="copyIgnore('${this.esc(ignoreAnnotation)}',this);event.stopPropagation()">Copy ignore annotation</button>
    </div>
  </article>`;
        }
        html2 += `</section>`;
      }
      return html2;
    })();

    // ── Risk narrative (executive summary) ─────────────────────────────────
    const topRisks = catEntries
      .filter(([, c]) => c.deduction > 0)
      .sort((a, b) => b[1].deduction - a[1].deduction)
      .slice(0, 3)
      .map(([k, c]) => c.label);
    const worst = findings.filter(f => f.severity === 'critical').slice(0, 3).map(f => f.title);
    const riskNarrative = findings.length === 0
      ? '<p>No security findings were detected in this scan. That is encouraging — but it is not proof of absence: maintain ongoing scanning and keep your threat-intel feeds fresh.</p>'
      : `<p>This scan found <strong>${bySeverity.critical} critical</strong> and <strong>${bySeverity.high} high</strong> severity findings across ${bucketEntries.length} risk categories. The highest-risk areas are <strong>${topRisks.join(', ') || '—'}</strong>.${worst.length ? ` Among the most urgent: <strong>${this.esc(worst.join('; '))}</strong>.` : ''}</p>
<p class="muted">Overall posture: <strong style="color:${gradeColors[scoreResult.grade.letter]}">${scoreResult.grade.letter} — ${scoreResult.grade.label}</strong>. Address critical findings immediately, then work down the remediation roadmap below.</p>`;

    const standardsCardsHTML = renderStandardsAlignment(findings, (s) => this.esc(s));

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Praxis AI Security Assessment — ${this.esc(projectName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0b1220;color:#dbe4f0;line-height:1.55}
a{color:#38bdf8;text-decoration:none}
a:hover{text-decoration:underline}
.layout{display:flex;min-height:100vh}
/* ── Sidebar ─────────────────────────────────────────────── */
.sidebar{position:fixed;top:0;left:0;bottom:0;width:250px;background:#0f1a2e;border-right:1px solid #1c2c47;padding:1.4rem 1rem;overflow-y:auto}
.sidebar .brand{font-size:1.05rem;font-weight:800;color:#38bdf8;margin-bottom:0.2rem;letter-spacing:.5px}
.sidebar .brand-sub{font-size:.7rem;color:#5b6b85;margin-bottom:1rem}
.sidebar .score-pill{display:flex;align-items:center;gap:.7rem;background:#152238;border-radius:10px;padding:.8rem;margin-bottom:1.2rem}
.sidebar .score-pill .g{font-size:1.6rem;font-weight:900;color:${gradeColors[scoreResult.grade.letter]}}
.sidebar .score-pill small{color:#8b9bb8;font-size:.68rem;display:block}
.nav-label{font-size:.62rem;letter-spacing:1.2px;text-transform:uppercase;color:#5b6b85;margin:1rem 0 .35rem}
.sidebar a.nav{display:block;padding:.32rem .5rem;border-radius:6px;color:#a9b7d0;font-size:.82rem}
.sidebar a.nav:hover{background:#1b2a44;color:#e6f0ff;text-decoration:none}
.sidebar a.nav-cat{font-size:.75rem;padding:.2rem .5rem .2rem 1rem}
.sidebar .legend{font-size:.68rem;color:#5b6b85;margin-top:1.4rem;line-height:1.6}
/* ── Main ────────────────────────────────────────────────── */
.main{margin-left:250px;flex:1;padding:2.2rem 2.6rem;max-width:1100px}
.hero{display:flex;align-items:center;gap:1.6rem;background:linear-gradient(135deg,#152238 0%,#0f1a2e 100%);border:1px solid #1c2c47;border-radius:16px;padding:2rem;margin-bottom:1.8rem}
.hero .grade-big{font-size:4.2rem;font-weight:900;color:${gradeColors[scoreResult.grade.letter]};line-height:1}
.hero h1{font-size:1.6rem;margin-bottom:.3rem}
.hero .sub{color:#8b9bb8;font-size:.85rem}
.hero .scoreline{font-size:2rem;font-weight:800;color:#e6f0ff}
.hero .right{margin-left:auto;text-align:right;font-size:.78rem;color:#5b6b85}
h2.sec{margin:2.6rem 0 1.1rem;padding-bottom:.5rem;border-bottom:1px solid #1c2c47;font-size:1.25rem;color:#c6d4ea;display:flex;align-items:center;gap:.6rem}
h2.sec .num{color:#38bdf8;font-size:.9rem}
/* stat cards */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.9rem;margin-bottom:1.6rem}
.stat{background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.1rem;text-align:center;cursor:pointer;transition:transform .15s}
.stat:hover{transform:translateY(-2px)}
.stat.active{outline:2px solid #38bdf8}
.stat-number{font-size:1.9rem;font-weight:800}
.stat-label{color:#7d8db0;font-size:.76rem;margin-top:.2rem}
/* category bars */
.chart{background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.3rem;margin-bottom:1.6rem}
.bar-row{display:flex;align-items:center;gap:.75rem;padding:.38rem 0}
.bar-label{width:200px;font-size:.8rem;color:#9db0cf;text-align:right;flex-shrink:0}
.bar-track{flex:1;height:18px;background:#0b1220;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px}
.bar-value{width:70px;font-size:.78rem;font-weight:700;flex-shrink:0}
.bar-count{width:90px;font-size:.72rem;color:#7d8db0;flex-shrink:0}
/* narrative */
.narrative{background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.3rem 1.5rem;margin-bottom:1.6rem;font-size:.92rem}
.narrative p{margin-bottom:.6rem}
.narrative p:last-child{margin-bottom:0}
.muted{color:#7d8db0}
/* finding categories + cards */
.cat-section{margin-bottom:1.8rem}
.cat-header{display:flex;justify-content:space-between;align-items:center;background:#111c31;border:1px solid #1c2c47;border-bottom:none;border-radius:12px 12px 0 0;padding:.85rem 1.2rem}
.cat-header h3{font-size:1.02rem;color:#c6d4ea}
.cat-count{font-size:.76rem;color:#7d8db0;background:#0b1220;border-radius:999px;padding:.25rem .8rem}
.finding-card{background:#111c31;border:1px solid #1c2c47;border-top:none;padding:0}
.cat-section .finding-card:last-child{border-radius:0 0 12px 12px}
.cat-section .finding-card:only-child{border-radius:0 0 12px 12px}
.card-head{display:flex;align-items:center;gap:1rem;padding:.9rem 1.2rem;cursor:pointer}
.card-head:hover{background:#152238}
.sev{display:inline-block;min-width:74px;text-align:center;border-radius:6px;padding:.2rem .5rem;font-size:.68rem;font-weight:800;letter-spacing:.5px}
.sev-critical{background:#3b0f16;color:#ff7b7b;border:1px solid #7f1d1d}
.sev-high{background:#3a1a08;color:#ffb26b;border:1px solid #92400e}
.sev-medium{background:#3a2f08;color:#ffd76b;border:1px solid #a16207}
.sev-low{background:#0f2340;color:#7db4ff;border:1px solid #1e40af}
.card-title{flex:1;font-size:.92rem}
.card-title strong{color:#e6f0ff}
.card-loc{font-size:.72rem;color:#7d8db0;font-family:ui-monospace,monospace}
.card-chips{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.deep-badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:.66rem;font-weight:700;color:#fff}
.conf-chip{display:inline-block;padding:1px 9px;border-radius:999px;font-size:.66rem;font-weight:600}
.conf-low{background:#334155;color:#cbd5e1}
.conf-medium{background:#b45309;color:#fff}
.eaa-chip{display:inline-block;padding:1px 9px;border-radius:999px;font-size:.66rem;font-weight:600;background:#4338ca;color:#e0e7ff}
.card-body{padding:1rem 1.3rem 1.2rem;border-top:1px solid #1c2c47;background:#0e1830;font-size:.88rem}
.card-body h4{font-size:.72rem;letter-spacing:1.1px;text-transform:uppercase;color:#38bdf8;margin:1rem 0 .35rem}
.card-body h4:first-child{margin-top:0}
.card-body p{margin-bottom:.5rem;color:#b9c6dc}
.fix-text{color:#7ee2a8}
.refs{font-size:.76rem;color:#8b9bb8}
.refs a{color:#38bdf8}
.deep-block{background:#0f2240;border-left:3px solid #38bdf8;border-radius:6px;padding:.7rem .9rem;margin:.7rem 0;font-size:.82rem;color:#9cc7f5}
.code-block{background:#070d18;border:1px solid #1c2c47;border-radius:8px;padding:.7rem;font-size:.76rem;margin:.4rem 0 .8rem;overflow-x:auto;line-height:1.45;font-family:ui-monospace,monospace;white-space:pre}
.copy-btn{background:#1b2a44;color:#38bdf8;border:1px solid #2c3f63;border-radius:6px;padding:4px 12px;font-size:.7rem;cursor:pointer;margin-top:.6rem}
.copy-btn:hover{background:#22355a}
.copy-btn.copied{background:#14532d;color:#7ee2a8;border-color:#22c55e}
/* filter bar */
.filter-bar{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:.8rem 1rem;margin-bottom:1.2rem;position:sticky;top:0;z-index:5}
.filter-btn{background:#1b2a44;color:#a9b7d0;border:1px solid #2c3f63;border-radius:999px;padding:4px 12px;font-size:.72rem;cursor:pointer}
.filter-btn.active{background:#38bdf8;color:#06121f;border-color:#38bdf8;font-weight:700}
.search-input{flex:1;min-width:180px;background:#0b1220;border:1px solid #2c3f63;border-radius:8px;color:#e6f0ff;padding:6px 12px;font-size:.8rem}
.search-input::placeholder{color:#5b6b85}
.count-label{font-size:.72rem;color:#7d8db0}
.hidden-row{display:none !important}
/* AI lanes */
.lane-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1rem}
.lane-card{background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.1rem;border-left:3px solid #38bdf8}
.lane-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:.4rem}
.lane-count{background:#1b2a44;border-radius:999px;padding:2px 10px;font-size:.68rem;color:#8b9bb8}
.lane-sev{font-size:.76rem;margin-bottom:.4rem}
.lane-top{margin:0;padding-left:1.1rem;font-size:.78rem;color:#8b9bb8}
.lane-top li{margin-bottom:.25rem}
/* tables */
table{width:100%;border-collapse:collapse;background:#111c31;border:1px solid #1c2c47;border-radius:12px;overflow:hidden;font-size:.85rem}
th{background:#152238;color:#9db0cf;text-align:left;padding:.7rem .9rem;font-size:.72rem;letter-spacing:.8px;text-transform:uppercase}
td{padding:.6rem .9rem;border-top:1px solid #1c2c47;color:#b9c6dc;vertical-align:top}
tr.sev-header td{background:#152238;font-weight:700}
/* standards gap */
.std-gap{background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.1rem 1.3rem}
.std-gap-row{padding:.6rem 0;border-bottom:1px solid #1c2c47;font-size:.86rem}
.std-gap-row:last-child{border-bottom:none}
.cov{font-size:.76rem;display:inline-block}
.cov-flagged{color:#ff7b7b}
.cov-nodata{color:#7d8db0}
.cov-gap{color:#d1a55c}
.legend-box{background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1rem 1.3rem;font-size:.8rem;color:#8b9bb8;margin-bottom:1.2rem}
.legend-box strong{color:#c6d4ea}
.trend-bar{display:inline-block;height:10px;border-radius:3px;margin-right:.5rem;vertical-align:middle}
/* footer */
.footer{margin-top:3rem;text-align:center;color:#5b6b85;font-size:.78rem;border-top:1px solid #1c2c47;padding-top:1.4rem}
.scope-note{margin:0 auto;max-width:760px;font-size:.72rem;color:#5b6b85;line-height:1.5;text-align:left;margin-top:1rem}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:1.2rem}}
</style>
</head>
<body>
<div class="layout">
  <nav class="sidebar">
    <div class="brand">PRAXIS</div>
    <div class="brand-sub">AI Security Assessment</div>
    <div class="score-pill">
      <span class="g">${scoreResult.grade.letter}</span>
      <span><small>SECURITY SCORE</small>${scoreResult.score}/100</span>
    </div>
    <div class="nav-label">Report</div>
    <a class="nav" href="#exec">1 · Executive Summary</a>
    <a class="nav" href="#categories">2 · Risk by Category</a>
    <a class="nav" href="#findings">3 · Detailed Findings</a>
    <div class="nav-label">Findings by category</div>
    ${bucketEntries.map(b => `<a class="nav nav-cat" href="#cat-${b.key}">${this.esc(b.label)} (${b.hits.length})</a>`).join('')}
    <div class="nav-label">More</div>
    <a class="nav" href="#ai-lanes">4 · AI Attack-Surface Lanes</a>
    <a class="nav" href="#plan">5 · Remediation Roadmap</a>
    <a class="nav" href="#standards">6 · Standards Compliance</a>
    <a class="nav" href="#surface">7 · Attack Surface</a>
    <a class="nav" href="#trend">8 · Security Trend</a>
    <div class="legend">
      <strong>Reading this report</strong><br>
      Every finding explains: <em>what it means</em>, the <em>evidence</em>, and <em>how to fix it</em>.<br><br>
      "No evidence in this scan" ≠ safe. It means the scanner found no matching pattern — which is not proof of absence.
    </div>
  </nav>

  <main class="main">
    <div class="hero">
      <div class="grade-big">${scoreResult.grade.letter}</div>
      <div>
        <h1>AI Security Assessment — ${this.esc(projectName)}</h1>
        <div class="sub">Generated ${date} · Praxis ${PKG_VERSION} · ${findings.length} findings · ${(depVulns || []).length} dependency CVEs</div>
        <div class="scoreline">${scoreResult.score}/100 <span style="font-size:.85rem;color:#8b9bb8">— ${scoreResult.grade.label}</span></div>
      </div>
      <div class="right">
        ${recon && recon.languages ? `<div>${(recon.languages || []).join(', ') || '—'}</div>` : ''}
        ${recon && recon.frameworks ? `<div>${(recon.frameworks || []).join(', ') || ''}</div>` : ''}
      </div>
    </div>

    <div class="stats" id="severity-stats">
      <div class="stat" onclick="toggleSevFilter('critical')" id="stat-critical"><div class="stat-number" style="color:${sevColors.critical}">${bySeverity.critical}</div><div class="stat-label">CRITICAL</div></div>
      <div class="stat" onclick="toggleSevFilter('high')" id="stat-high"><div class="stat-number" style="color:${sevColors.high}">${bySeverity.high}</div><div class="stat-label">HIGH</div></div>
      <div class="stat" onclick="toggleSevFilter('medium')" id="stat-medium"><div class="stat-number" style="color:${sevColors.medium}">${bySeverity.medium}</div><div class="stat-label">MEDIUM</div></div>
      <div class="stat" onclick="toggleSevFilter('low')" id="stat-low"><div class="stat-number" style="color:${sevColors.low}">${bySeverity.low}</div><div class="stat-label">LOW</div></div>
    </div>

    <h2 class="sec" id="exec"><span class="num">1</span> Executive Summary</h2>
    <div class="narrative">${riskNarrative}</div>
    <div class="summary-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:.9rem;margin-bottom:1.6rem">
      <div class="summary-card" style="background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.1rem"><h3 style="color:#38bdf8;font-size:.85rem;margin-bottom:.4rem">Dependency CVEs</h3><div class="big" style="font-size:1.8rem;font-weight:800;color:${(depVulns || []).length > 0 ? '#ff7b7b' : '#7ee2a8'}">${(depVulns || []).length}</div></div>
      <div class="summary-card" style="background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.1rem"><h3 style="color:#38bdf8;font-size:.85rem;margin-bottom:.4rem">Risk Categories</h3><div class="big" style="font-size:1.8rem;font-weight:800">${bucketEntries.length}</div></div>
    </div>

    <h2 class="sec" id="categories"><span class="num">2</span> Risk by Category</h2>
    <div class="chart">
      ${categoryBars}
    </div>

    <h2 class="sec" id="findings"><span class="num">3</span> Detailed Findings</h2>
    <div class="filter-bar">
      <label style="font-size:.72rem;color:#7d8db0">Filter:</label>
      <button class="filter-btn active" data-sev="all" onclick="filterSev('all',this)">All</button>
      <button class="filter-btn" data-sev="critical" onclick="filterSev('critical',this)">Critical</button>
      <button class="filter-btn" data-sev="high" onclick="filterSev('high',this)">High</button>
      <button class="filter-btn" data-sev="medium" onclick="filterSev('medium',this)">Medium</button>
      <button class="filter-btn" data-sev="low" onclick="filterSev('low',this)">Low</button>
      <input class="search-input" type="text" placeholder="Search findings..." oninput="searchFindings(this.value)">
      <span class="count-label" id="visible-count">${findings.length} shown</span>
    </div>
    ${findingCards || '<p class="muted">No findings — clean scan.</p>'}

    <h2 class="sec" id="ai-lanes"><span class="num">4</span> AI Attack-Surface Lanes</h2>
    <p class="muted" style="margin-bottom:1rem">Findings grouped by AI-security lane — Praxis's first-class focus.</p>
    ${aiLaneHTML}

    <h2 class="sec" id="plan"><span class="num">5</span> Remediation Roadmap</h2>
    <p class="muted" style="margin-bottom:1rem">Prioritized list of fixes. Address critical items first.</p>
    ${(remediationPlan || []).length > 0 ? `<table>
      <thead><tr><th>#</th><th>Category</th><th>Issue</th><th>Location</th><th>Fix</th></tr></thead>
      <tbody>${planHTML}</tbody>
    </table>` : '<p style="color:#7ee2a8;font-weight:700">No issues found — all clear!</p>'}

    <h2 class="sec" id="standards"><span class="num">6</span> Standards Compliance</h2>
    <div class="legend-box">
      <strong>How to read the coverage map.</strong> Praxis tags every finding with the AI-security standards it maps to (OWASP LLM/ML/Agentic, MITRE ATLAS, NIST AI 600-1, AVID, EU AI Act, ISO 42001, Google SAIF). Three states:
      <span class="cov cov-flagged">Flagged</span> — this scan produced evidence for that control ·
      <span class="cov cov-nodata">No evidence in this scan</span> — the tool can detect it, this repo showed nothing (NOT proof of safety) ·
      <span class="cov cov-gap">No detection rule</span> — Praxis has no code-level check for this control (e.g. registration duties, impact assessments). Evidence-based mapping — not a compliance certification.
    </div>
    <div class="std-gap">${standardsGapHTML}</div>
    ${renderStandardsAlignment(findings, (s) => this.esc(s)) ? `<div style="margin-top:1.2rem">${renderStandardsAlignment(findings, (s) => this.esc(s))}</div>` : ''}

    ${recon ? `<h2 class="sec" id="surface"><span class="num">7</span> Attack Surface</h2>
    <table>
      <tbody>
        <tr><td><strong>Frameworks</strong></td><td>${(recon.frameworks || []).join(', ') || 'None detected'}</td></tr>
        <tr><td><strong>Languages</strong></td><td>${(recon.languages || []).join(', ') || 'None detected'}</td></tr>
        <tr><td><strong>Databases</strong></td><td>${(recon.databases || []).join(', ') || 'None detected'}</td></tr>
        <tr><td><strong>Cloud Providers</strong></td><td>${(recon.cloudProviders || []).join(', ') || 'None detected'}</td></tr>
        <tr><td><strong>Auth Patterns</strong></td><td>${(recon.authPatterns || []).join(', ') || 'None detected'}</td></tr>
        <tr><td><strong>CI/CD</strong></td><td>${(recon.cicd || []).map(c => c.platform).join(', ') || 'None detected'}</td></tr>
        <tr><td><strong>API Routes</strong></td><td>${(recon.apiRoutes || []).length} discovered</td></tr>
      </tbody>
    </table>` : ''}

    <h2 class="sec" id="trend"><span class="num">8</span> Security Trend</h2>
    ${trendHTML}

    <div class="footer">
      Generated by <strong>Praxis</strong> — AI-native security scan (find → fix → verify)<br>
      <a href="https://github.com/Ganron007/Praxis">github.com/Ganron007/Praxis</a>
      <div class="scope-note">
        <strong>Scope &amp; limitations.</strong> Praxis is an AI-security-first scanner: it complements — not
        replaces — Semgrep/CodeQL-class SAST. Detection is regex + LLM-assisted (no AST/dataflow);
        a clean scan is not proof of absence. Standards mapping reports controls for which evidence was
        found, not certification of compliance. Review every finding before acting; prefer the
        find→fix→verify loop for remediation.
      </div>
    </div>
  </main>
</div>

<script>
function toggleCard(idx) {
  const el = document.getElementById('card-' + idx);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

let activeSev = 'all';
let searchTerm = '';

function filterSev(sev, btn) {
  activeSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}

function toggleSevFilter(sev) {
  const btn = document.querySelector('.filter-btn[data-sev="' + sev + '"]');
  if (activeSev === sev) filterSev('all', document.querySelector('.filter-btn[data-sev="all"]'));
  else if (btn) filterSev(sev, btn);
}

function searchFindings(term) {
  searchTerm = term.toLowerCase();
  applyFilters();
}

function applyFilters() {
  const cards = document.querySelectorAll('.finding-card');
  let visible = 0;
  cards.forEach(card => {
    const matchSev = activeSev === 'all' || card.dataset.sev === activeSev;
    const matchSearch = !searchTerm || card.dataset.text.includes(searchTerm);
    if (matchSev && matchSearch) { card.classList.remove('hidden-row'); visible++; }
    else { card.classList.add('hidden-row'); }
  });
  const sections = document.querySelectorAll('.cat-section');
  sections.forEach(sec => {
    const vis = sec.querySelectorAll('.finding-card:not(.hidden-row)').length;
    sec.style.display = vis === 0 ? 'none' : '';
  });
  document.getElementById('visible-count').textContent = visible + ' shown';
  document.querySelectorAll('.stat').forEach(s => s.classList.remove('active'));
  if (activeSev !== 'all') {
    const el = document.getElementById('stat-' + activeSev);
    if (el) el.classList.add('active');
  }
}

function copyIgnore(text, btn) {
  navigator.clipboard.writeText('// ' + text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy ignore annotation'; btn.classList.remove('copied'); }, 2000);
  });
}
</script>
</body>
</html>`;


    fs.writeFileSync(outputPath, html);
    return outputPath;
  }

  /** Escape HTML entities */
  esc(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}

export default HTMLReporter;