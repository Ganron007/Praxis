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
import { getComplianceSummary } from '../utils/compliance-map.js';
import { getStandardsSummary } from '../utils/standards/index.js';

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

    // ── Standards coverage gap map (P-IMP-024) ─────────────────────────────
    const standardsGapHTML = (scoreResult.standardsSummary
      ? Object.entries(scoreResult.standardsSummary)
        .map(([stdName, std]) => {
          const flagged = (std.controls || []).filter(c => c.status === 'flagged');
          const clear = (std.controls || []).filter(c => c.status !== 'flagged');
          const flaggedLine = flagged.length > 0
            ? `<span style="color:#ef4444">Flagged (${flagged.length}): ${flagged.map(c => this.esc(c.id)).join(', ')}</span>`
            : '<span style="color:#22c55e">All controls clear</span>';
          const clearLine = clear.length > 0
            ? `<br><span style="color:#64748b">Not covered (${clear.length}): ${clear.map(c => this.esc(c.id)).join(', ')}</span>`
            : '';
          return `<div class="std-gap-row"><strong>${this.esc(std.title || stdName)}</strong> — ${std.coverage} controls flagged<div style="font-size:0.75rem">${flaggedLine}${clearLine}</div></div>`;
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

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Praxis Full Audit Report — ${this.esc(projectName)}</title>
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
.stat{background:#1e293b;padding:1.5rem;border-radius:8px;text-align:center;cursor:pointer;transition:transform .15s,box-shadow .15s}
.stat:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.3)}
.stat.active{outline:2px solid #38bdf8}
.stat-number{font-size:2rem;font-weight:bold}
.stat-label{color:#64748b;font-size:0.85rem}
.summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem}
.summary-card{background:#1e293b;padding:1.5rem;border-radius:8px}
.summary-card h3{color:#38bdf8;font-size:1rem;margin-bottom:0.5rem}
.summary-card .big{font-size:2.5rem;font-weight:bold}
/* Bar chart */
.chart{background:#1e293b;border-radius:8px;padding:1.5rem;margin-bottom:2rem}
.bar-row{display:flex;align-items:center;gap:0.75rem;padding:0.4rem 0}
.bar-label{width:160px;font-size:0.8rem;color:#94a3b8;text-align:right;flex-shrink:0}
.bar-track{flex:1;height:20px;background:#0f172a;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
.bar-value{width:70px;font-size:0.8rem;font-weight:bold;flex-shrink:0}
.bar-count{width:80px;font-size:0.75rem;color:#64748b;flex-shrink:0}
/* Filter bar */
.filter-bar{display:flex;align-items:center;gap:1rem;background:#1e293b;padding:1rem 1.5rem;border-radius:8px;margin-bottom:1rem;flex-wrap:wrap}
.filter-bar label{font-size:0.8rem;color:#94a3b8}
.filter-btn{padding:4px 12px;border-radius:4px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;cursor:pointer;font-size:0.8rem;transition:background .15s}
.filter-btn.active{border-color:#38bdf8;background:#38bdf822}
.filter-btn:hover{background:#334155}
.search-input{background:#0f172a;border:1px solid #334155;border-radius:4px;padding:6px 12px;color:#e2e8f0;font-size:0.8rem;width:200px}
.search-input:focus{outline:none;border-color:#38bdf8}
.filter-bar .count-label{margin-left:auto;font-size:0.8rem;color:#64748b}
/* Table */
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;margin-bottom:2rem}
th{background:#334155;text-align:left;padding:0.75rem 1rem;font-size:0.8rem;text-transform:uppercase;color:#94a3b8;cursor:pointer;user-select:none}
th:hover{color:#e2e8f0}
td{padding:0.75rem 1rem;border-top:1px solid #0f172a;font-size:0.85rem;vertical-align:top}
tr:hover{background:#334155}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.8rem;color:#38bdf8;word-break:break-all}
small{color:#94a3b8}
.sev{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:bold;text-transform:uppercase;white-space:nowrap}
.sev-critical{background:#dc262633;color:#fca5a5}
.sev-high{background:#f9731633;color:#fdba74}
.sev-medium,.sev-moderate{background:#eab30833;color:#fde047}
.sev-low{background:#3b82f633;color:#93c5fd}
/* Collapsible findings */
.finding-title{cursor:pointer;border-bottom:1px dashed #475569}
.finding-title:hover{color:#38bdf8}
.finding-detail{margin-top:0.5rem;padding:0.75rem;background:#0f172a;border-radius:6px;border-left:3px solid #38bdf8}
.finding-detail p{font-size:0.8rem;color:#94a3b8;margin-bottom:0.4rem}
.finding-meta{font-size:0.75rem;color:#64748b}
.finding-fix{color:#22c55e;font-size:0.8rem}
.code-block{background:#020617;padding:0.5rem;border-radius:4px;font-size:0.75rem;margin:0.5rem 0;overflow-x:auto;line-height:1.4}
.copy-btn{background:#334155;color:#38bdf8;border:1px solid #475569;border-radius:4px;padding:3px 10px;font-size:0.7rem;cursor:pointer;margin-top:0.4rem}
.copy-btn:hover{background:#475569}
.copy-btn.copied{background:#22c55e33;color:#22c55e;border-color:#22c55e}
/* LLM deep-analysis verdict, confidence, and EAA chips */
.deep-badge{display:inline-block;margin-left:0.5rem;padding:1px 8px;border-radius:999px;font-size:0.68rem;font-weight:700;color:#fff;vertical-align:middle}
.conf-chip{display:inline-block;margin-left:0.5rem;padding:1px 8px;border-radius:999px;font-size:0.68rem;font-weight:600;vertical-align:middle}
.conf-low{background:#475569;color:#cbd5e1}
.conf-medium{background:#b45309;color:#fff}
.eaa-chip{display:inline-block;margin-left:0.5rem;padding:1px 8px;border-radius:999px;font-size:0.68rem;font-weight:600;background:#4f46e5;color:#e0e7ff;vertical-align:middle}
.finding-deep{color:#7dd3fc;font-size:0.8rem;margin-bottom:0.4rem}
.finding-deep strong{color:#38bdf8}
/* TOC */
.toc{background:#1e293b;padding:1.5rem 2rem;border-radius:8px;margin-bottom:2rem}
.toc a{color:#38bdf8;text-decoration:none;display:block;padding:0.3rem 0}
.toc a:hover{text-decoration:underline}
.footer{text-align:center;color:#475569;margin-top:3rem;padding:2rem;border-top:1px solid #1e293b}
.footer a{color:#38bdf8}
.scope-note{margin:0 auto;max-width:760px;font-size:0.72rem;color:#64748b;line-height:1.5;text-align:left}
/* AI lanes, standards gap, trend */
.lane-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1rem}
.lane-card{background:#1e293b;border-radius:8px;padding:1rem;border-left:3px solid #38bdf8}
.lane-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem}
.lane-count{background:#334155;border-radius:999px;padding:2px 10px;font-size:0.7rem;color:#94a3b8}
.lane-sev{font-size:0.75rem;margin-bottom:0.4rem}
.lane-top{margin:0;padding-left:1.1rem;font-size:0.78rem;color:#94a3b8}
.lane-top li{margin-bottom:0.25rem}
.std-gap{background:#1e293b;border-radius:8px;padding:1rem}
.std-gap-row{padding:0.55rem 0;border-bottom:1px solid #0f172a;font-size:0.85rem}
.std-gap-row:last-child{border-bottom:none}
.trend-bar{display:inline-block;height:10px;border-radius:3px;margin-right:0.5rem;vertical-align:middle}
.share-bar{display:flex;justify-content:center;gap:0.75rem;margin:1.5rem 0}
.share-btn{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:6px;font-size:0.85rem;font-weight:600;text-decoration:none;cursor:pointer;border:none;transition:opacity .15s}
.share-btn:hover{opacity:0.85}
.share-btn-x{background:#000;color:#fff}
.share-btn-li{background:#0a66c2;color:#fff}
.share-btn-copy{background:#334155;color:#38bdf8;border:1px solid #475569}
.share-btn-copy.copied{background:#22c55e33;color:#22c55e;border-color:#22c55e}
.badge-section{background:#1e293b;border-radius:8px;padding:1.5rem;margin-top:1.5rem;text-align:center}
.badge-section img{margin-bottom:0.75rem}
.badge-section code{display:block;background:#0f172a;padding:8px 12px;border-radius:4px;font-size:0.75rem;margin-top:0.5rem;word-break:break-all;user-select:all}
/* Hidden row */
.hidden-row{display:none}
/* Print */
@media print{
  body{background:#fff;color:#1e293b}
  table,th,td{border:1px solid #e2e8f0}
  .score-card,.stat,.summary-card,.toc,.chart,.filter-bar{background:#f8fafc}
  .copy-btn,.search-input{display:none}
  .finding-detail{display:block!important}
}
</style>
</head>
<body>
<div class="container">
  <h1>Praxis — Full Security Audit Report</h1>
  <p class="meta">${this.esc(projectName)} — ${date}</p>

  <div class="toc">
    <strong>Contents</strong>
    <a href="#score">1. Security Score</a>
    <a href="#summary">2. Executive Summary</a>
    <a href="#categories">3. Category Breakdown</a>
    <a href="#plan">4. Remediation Plan (${(remediationPlan || []).length} items)</a>
    <a href="#findings">5. All Findings (${findings.length})</a>
    <a href="#deps">6. Dependency Vulnerabilities (${(depVulns || []).length})</a>
    <a href="#standards">7. AI Security Standards Alignment</a>
    <a href="#surface">8. Attack Surface</a>
    <a href="#ai-lanes">9. AI Attack-Surface Lanes</a>
    <a href="#trend">10. Security Trend</a>
  </div>

  <h2 id="score">1. Security Score</h2>
  <div class="score-card">
    <div class="grade" style="background:${gradeColors[scoreResult.grade.letter]}22;color:${gradeColors[scoreResult.grade.letter]}">${scoreResult.grade.letter}</div>
    <div>
      <div class="score-number" style="color:${gradeColors[scoreResult.grade.letter]}">${scoreResult.score}/100</div>
      <div style="color:#94a3b8">${scoreResult.grade.label}</div>
    </div>
  </div>

  <div class="stats" id="severity-stats">
    <div class="stat" onclick="toggleSevFilter('critical')" id="stat-critical"><div class="stat-number" style="color:${sevColors.critical}">${bySeverity.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat" onclick="toggleSevFilter('high')" id="stat-high"><div class="stat-number" style="color:${sevColors.high}">${bySeverity.high}</div><div class="stat-label">High</div></div>
    <div class="stat" onclick="toggleSevFilter('medium')" id="stat-medium"><div class="stat-number" style="color:${sevColors.medium}">${bySeverity.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat" onclick="toggleSevFilter('low')" id="stat-low"><div class="stat-number" style="color:${sevColors.low}">${bySeverity.low}</div><div class="stat-label">Low</div></div>
  </div>

  <h2 id="summary">2. Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <h3>Code Findings</h3>
      <div class="big" style="color:${findings.length > 0 ? '#ef4444' : '#22c55e'}">${findings.length}</div>
      <small>Across ${Object.keys(scoreResult.categories).length} categories</small>
    </div>
    <div class="summary-card">
      <h3>Dependency CVEs</h3>
      <div class="big" style="color:${(depVulns || []).length > 0 ? '#ef4444' : '#22c55e'}">${(depVulns || []).length}</div>
      <small>From npm/pip/bundler audit</small>
    </div>
  </div>

  <h2 id="categories">3. Category Breakdown</h2>
  <div class="chart">
    ${categoryBars}
  </div>

  <h2 id="plan">4. Remediation Plan</h2>
  <p style="color:#94a3b8;margin-bottom:1rem">Prioritized list of fixes. Address critical items first.</p>
  ${(remediationPlan || []).length > 0 ? `<table>
    <thead><tr><th>#</th><th>Category</th><th>Issue</th><th>Location</th><th>Fix</th></tr></thead>
    <tbody>${planHTML}</tbody>
  </table>` : '<p style="color:#22c55e;font-weight:bold">No issues found — all clear!</p>'}

  <h2 id="findings">5. All Findings (${findings.length})</h2>
  <div class="filter-bar">
    <label>Filter:</label>
    <button class="filter-btn active" data-sev="all" onclick="filterSev('all',this)">All</button>
    <button class="filter-btn" data-sev="critical" onclick="filterSev('critical',this)">Critical (${bySeverity.critical})</button>
    <button class="filter-btn" data-sev="high" onclick="filterSev('high',this)">High (${bySeverity.high})</button>
    <button class="filter-btn" data-sev="medium" onclick="filterSev('medium',this)">Medium (${bySeverity.medium})</button>
    <button class="filter-btn" data-sev="low" onclick="filterSev('low',this)">Low (${bySeverity.low})</button>
    <input class="search-input" type="text" placeholder="Search findings..." oninput="searchFindings(this.value)">
    <span class="count-label" id="visible-count">${findings.length} shown</span>
  </div>
  <table id="findings-table">
    <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Code</th><th>Fix</th></tr></thead>
    <tbody>${findingRows || '<tr><td colspan="5" style="text-align:center;color:#22c55e">No findings — clean!</td></tr>'}</tbody>
  </table>

  <h2 id="deps">6. Dependency Vulnerabilities (${(depVulns || []).length})</h2>
  ${(depVulns || []).length > 0 ? `<table>
    <thead><tr><th>Severity</th><th>Package</th><th>Description</th></tr></thead>
    <tbody>${depRows}</tbody>
  </table>` : '<p style="color:#22c55e;font-weight:bold">No vulnerable dependencies found.</p>'}

  <h2 id="standards">7. AI Security Standards Alignment</h2>
  <p style="color:#94a3b8;margin-bottom:1rem">Each finding is auto-tagged with all applicable AI-security standards.</p>
  ${renderStandardsAlignment(findings, (s) => this.esc(s))}
  <h3 style="margin:1.5rem 0 0.75rem">Standards coverage map</h3>
  <p style="color:#94a3b8;font-size:0.8rem;margin-bottom:1rem">Controls for which this scan produced evidence (flagged) vs controls with no evidence (not covered). Evidence-based mapping — not a compliance certification.</p>
  <div class="std-gap">${standardsGapHTML}</div>

  ${recon ? `<h2 id="surface">8. Attack Surface</h2>
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

  <h2 id="ai-lanes">9. AI Attack-Surface Lanes</h2>
  <p style="color:#94a3b8;margin-bottom:1rem">Findings grouped by AI-security lane — Praxis's first-class focus.</p>
  ${aiLaneHTML}

  <h2 id="trend">10. Security Trend</h2>
  <p style="color:#94a3b8;margin-bottom:1rem">Score history from repeated scans in this project.</p>
  ${trendHTML}

  <div class="share-bar">
    <button class="share-btn share-btn-copy" onclick="copyShareText(this)">Copy Score Summary</button>
  </div>

  <div class="badge-section">
    <p style="color:#94a3b8;margin-bottom:0.75rem"><strong>Add a security badge to your README:</strong></p>
    <img src="https://img.shields.io/badge/Praxis-${scoreResult.grade.letter}-${gradeColors[scoreResult.grade.letter].replace('#','')}" alt="Praxis Grade ${scoreResult.grade.letter}" />
    <code>[![Praxis](https://img.shields.io/badge/Praxis-${scoreResult.grade.letter}-${gradeColors[scoreResult.grade.letter].replace('#','')})]()</code>
  </div>

  <div class="footer">
    Generated by <strong>Praxis</strong> — AI-native security scan (find &rarr; fix &rarr; verify)<br>
    <a href="https://github.com/Ganron007/Praxis">github.com/Ganron007/Praxis</a>
    <div class="scope-note">
      <strong>Scope &amp; limitations.</strong> Praxis is an AI-security-first scanner: it complements — not
      replaces — Semgrep/CodeQL-class SAST. Detection is regex + LLM-assisted (no AST/dataflow);
      a clean report is not proof of absence. Standards mapping reports controls for which evidence was
      found, not certification of compliance. Review every finding before acting; prefer the
      find&rarr;fix&rarr;verify loop for remediation.
    </div>
  </div>
</div>

<script>
function copyShareText(btn) {
  const text = 'My project scored ${scoreResult.score}/100 (Grade ${scoreResult.grade.letter}) on Praxis security audit!\\nScan yours: npx praxis audit .\\n';
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy Score Summary'; btn.classList.remove('copied'); }, 2000);
  });
}

// ── Severity filter ────────────────────────────────────────────────────────
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
  if (activeSev === sev) {
    filterSev('all', document.querySelector('.filter-btn[data-sev="all"]'));
  } else if (btn) {
    filterSev(sev, btn);
  }
}

function searchFindings(term) {
  searchTerm = term.toLowerCase();
  applyFilters();
}

function applyFilters() {
  const rows = document.querySelectorAll('.finding-row');
  let visible = 0;
  rows.forEach(row => {
    const matchSev = activeSev === 'all' || row.dataset.sev === activeSev;
    const matchSearch = !searchTerm || row.dataset.text.includes(searchTerm);
    if (matchSev && matchSearch) {
      row.classList.remove('hidden-row');
      visible++;
    } else {
      row.classList.add('hidden-row');
    }
  });
  document.getElementById('visible-count').textContent = visible + ' shown';

  // Highlight active stat card
  document.querySelectorAll('.stat').forEach(s => s.classList.remove('active'));
  if (activeSev !== 'all') {
    const el = document.getElementById('stat-' + activeSev);
    if (el) el.classList.add('active');
  }
}

// ── Collapsible detail ─────────────────────────────────────────────────────
function toggleDetail(idx) {
  const el = document.getElementById('detail-' + idx);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

// ── Copy ignore annotation ─────────────────────────────────────────────────
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
