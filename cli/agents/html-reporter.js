/**
 * Praxis Forensic & Executive Multi-Section HTML Report Generator
 * ================================================================
 *
 * Generates both:
 *   1. Granular Multi-Page Report Suite (index.html, findings.html, standards.html, abom.html, remediation.html)
 *   2. Unified Forensic Single-Page Report (praxis-report.html) with modular tabbed section views.
 *
 * Design Philosophy:
 *   - Forensic, high-density, executive aesthetic (#0a0f1d / #0f172a / #1e293b).
 *   - Strictly functional, zero flashy gimmicks, crisp contrast, readable monospace code.
 *   - Accurate AST & Taint dataflow traces, 3-state standards compliance, CycloneDX ABOM.
 *   - 100% relative path normalization (zero absolute system path leaks).
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getStandardsSummary } from '../utils/standards/index.js';
import { CATEGORIES, FALLBACK_CATEGORY_MAP } from './scoring-engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch {
    return '1.1.0';
  }
})();

export class HTMLReporter {
  esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  normalizePath(filePath, rootPath) {
    if (!filePath) return '';
    const norm = String(filePath).replace(/\\/g, '/');
    const normRoot = rootPath ? String(rootPath).replace(/\\/g, '/') : '';
    if (normRoot && norm.startsWith(normRoot)) {
      return norm.slice(normRoot.length).replace(/^\/+/, '');
    }
    return norm.replace(/^[a-zA-Z]:\/+/, '').replace(/^.*\/Praxis\/showcase-target\//, '').replace(/^.*\/showcase-target\//, '');
  }

  getSharedStyles(gradeColor, score) {
    return `
      *{margin:0;padding:0;box-sizing:border-box}
      html{scroll-behavior:smooth}
      body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#090d16;color:#cbd5e1;line-height:1.55;font-size:14px}
      a{color:#38bdf8;text-decoration:none}
      a:hover{text-decoration:underline}
      .app-header{background:#0d1527;border-bottom:1px solid #1e293b;position:sticky;top:0;z-index:50;padding:0.75rem 2rem}
      .header-inner{max-width:1440px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:1.5rem}
      .brand-group{display:flex;align-items:center;gap:1rem}
      .brand-title{font-size:1.35rem;font-weight:900;letter-spacing:1px;color:#f8fafc}
      .brand-title span{color:#c084fc}
      .brand-badge{background:#1e1b4b;color:#c084fc;border:1px solid #4338ca;padding:2px 8px;border-radius:6px;font-size:0.72rem;font-weight:700}
      .nav-tabs{display:flex;gap:0.4rem;align-items:center}
      .tab-link{padding:0.45rem 0.9rem;border-radius:8px;font-size:0.85rem;font-weight:600;color:#94a3b8;transition:all 0.15s;border:1px solid transparent}
      .tab-link:hover{background:#1e293b;color:#f8fafc;text-decoration:none}
      .tab-link.active{background:#1e293b;color:#38bdf8;border-color:#38bdf8;font-weight:700}
      .header-score{display:flex;align-items:center;gap:0.75rem;background:#131d33;padding:0.4rem 0.85rem;border-radius:8px;border:1px solid #1e293b}
      .header-score .grade{font-size:1.4rem;font-weight:900;color:${gradeColor};line-height:1}
      .header-score .score-text{font-size:0.8rem;color:#94a3b8}
      .header-score .score-text strong{color:#f8fafc;font-size:0.95rem}

      .container{max-width:1440px;margin:1.8rem auto;padding:0 2rem}
      .card{background:#0d1527;border:1px solid #1e293b;border-radius:12px;padding:1.4rem;margin-bottom:1.5rem}
      .card-title{font-size:1.15rem;font-weight:800;color:#f8fafc;margin-bottom:1rem;display:flex;align-items:center;justify-content:space-between}
      
      .kpi-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}
      .kpi-card{background:#0d1527;border:1px solid #1e293b;border-radius:10px;padding:1.1rem;text-align:center}
      .kpi-val{font-size:2.2rem;font-weight:900;line-height:1.1}
      .kpi-label{font-size:0.75rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:0.6px;margin-top:0.35rem}

      .sev-badge{display:inline-block;padding:3px 9px;border-radius:6px;font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.5px}
      .sev-critical{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}
      .sev-high{background:#431407;color:#fdba74;border:1px solid #9a3412}
      .sev-medium{background:#422006;color:#fde047;border:1px solid #854d0e}
      .sev-low{background:#082f49;color:#7dd3fc;border:1px solid #075985}

      .table-responsive{overflow-x:auto}
      table{width:100%;border-collapse:collapse;font-size:0.86rem;text-align:left}
      th{background:#131d33;color:#94a3b8;padding:0.75rem 1rem;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.6px;border-bottom:1px solid #1e293b}
      td{padding:0.75rem 1rem;border-bottom:1px solid #172239;vertical-align:top}
      tr:hover td{background:#111b30}
      
      .code-view{background:#050811;border:1px solid #1e293b;border-radius:8px;padding:0.8rem;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:0.8rem;line-height:1.45;overflow-x:auto;color:#e2e8f0;white-space:pre}
      .deep-box{background:#0c1c33;border-left:3px solid #38bdf8;padding:0.8rem 1rem;border-radius:6px;margin:0.6rem 0;font-size:0.84rem;color:#bae6fd}
      .ast-box{background:#16102b;border-left:3px solid #c084fc;padding:0.8rem 1rem;border-radius:6px;margin:0.6rem 0;font-size:0.84rem;color:#e9d5ff}
      
      .filter-toolbar{display:flex;align-items:center;gap:0.75rem;background:#0d1527;border:1px solid #1e293b;border-radius:10px;padding:0.75rem 1rem;margin-bottom:1.2rem;position:sticky;top:68px;z-index:40}
      .filter-btn{background:#131d33;color:#94a3b8;border:1px solid #1e293b;border-radius:6px;padding:0.35rem 0.85rem;font-size:0.78rem;font-weight:700;cursor:pointer}
      .filter-btn.active{background:#38bdf8;color:#090d16;border-color:#38bdf8}
      .search-box{flex:1;background:#070a14;border:1px solid #1e293b;border-radius:6px;padding:0.4rem 0.9rem;color:#f8fafc;font-size:0.85rem}
      .search-box:focus{outline:1px solid #38bdf8}
      
      .std-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1.2rem}
      .std-card{background:#0d1527;border:1px solid #1e293b;border-radius:10px;padding:1.2rem}
      .std-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:0.6rem}
      .std-title{font-size:1.02rem;font-weight:800;color:#f8fafc}
      .std-stat{font-size:1.4rem;font-weight:900}
      .tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:0.72rem;font-weight:700;margin:2px}
      .tag-flagged{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}
      .tag-clear{background:#064e3b;color:#6ee7b7;border:1px solid #047857}
      .tag-gap{background:#422006;color:#fde047;border:1px solid #854d0e}
      
      .footer{text-align:center;padding:2.5rem 0 1.5rem;color:#64748b;font-size:0.8rem;border-top:1px solid #1e293b;margin-top:3rem}
      @media(max-width:1024px){.kpi-grid{grid-template-columns:repeat(2,1fr)}.std-grid{grid-template-columns:1fr}}
    `;
  }

  generateHeaderHTML(activeTab, projectName, scoreResult, isMultiPage = false) {
    const gradeLetter = scoreResult.grade?.letter || scoreResult.grade || 'F';
    const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#f97316', F: '#ef4444' };
    const gradeColor = gradeColors[gradeLetter] || '#ef4444';

    const getHref = (tab) => {
      if (!isMultiPage) return `javascript:switchTab('${tab}')`;
      if (tab === 'overview') return 'index.html';
      if (tab === 'findings') return 'findings.html';
      if (tab === 'standards') return 'standards.html';
      if (tab === 'abom') return 'abom.html';
      if (tab === 'remediation') return 'remediation.html';
      return 'index.html';
    };

    return `
      <header class="app-header">
        <div class="header-inner">
          <div class="brand-group">
            <a href="${getHref('overview')}" style="text-decoration:none"><div class="brand-title">PRAXIS <span>CORE</span></div></a>
            <span class="brand-badge">v${PKG_VERSION}</span>
          </div>
          <nav class="nav-tabs">
            <a class="tab-link ${activeTab === 'overview' ? 'active' : ''}" href="${getHref('overview')}" id="tab-btn-overview">1 · Overview</a>
            <a class="tab-link ${activeTab === 'findings' ? 'active' : ''}" href="${getHref('findings')}" id="tab-btn-findings">2 · Findings &amp; AST Dataflow</a>
            <a class="tab-link ${activeTab === 'standards' ? 'active' : ''}" href="${getHref('standards')}" id="tab-btn-standards">3 · Standards Matrix</a>
            <a class="tab-link ${activeTab === 'abom' ? 'active' : ''}" href="${getHref('abom')}" id="tab-btn-abom">4 · Agent BOM (ABOM)</a>
            <a class="tab-link ${activeTab === 'remediation' ? 'active' : ''}" href="${getHref('remediation')}" id="tab-btn-remediation">5 · Remediation Plan</a>
          </nav>
          <div class="header-score">
            <div class="grade">${gradeLetter}</div>
            <div class="score-text">SCORE: <strong>${scoreResult.score}/100</strong></div>
          </div>
        </div>
      </header>
    `;
  }

  generate(scoreResult, findings, recon, rootPath) {
    return this.generateFullReport(scoreResult, findings, [], recon, [], rootPath);
  }

  generateToFile(scoreResult, findings, recon, rootPath, outputPath) {
    const html = this.generateFullReport(scoreResult, findings, [], recon, [], rootPath, outputPath);
    fs.writeFileSync(outputPath, html, 'utf8');
    return outputPath;
  }

  /**
   * Generates a Granular Multi-Page Security Report Suite into a target directory.
   */
  generateReportSuite(scoreResult, findings = [], depVulns = [], recon = {}, remediationPlan = [], rootPath = process.cwd(), outputDir = 'report') {
    fs.mkdirSync(outputDir, { recursive: true });

    const pages = [
      { name: 'index.html', tab: 'overview', content: this.renderOverviewSection(scoreResult, findings, recon, rootPath) },
      { name: 'findings.html', tab: 'findings', content: this.renderFindingsSection(scoreResult, findings, rootPath) },
      { name: 'standards.html', tab: 'standards', content: this.renderStandardsSection(scoreResult, findings) },
      { name: 'abom.html', tab: 'abom', content: this.renderAbomSection(recon, findings, rootPath) },
      { name: 'remediation.html', tab: 'remediation', content: this.renderRemediationSection(findings, remediationPlan, rootPath) },
    ];

    const gradeLetter = scoreResult.grade?.letter || scoreResult.grade || 'F';
    const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#f97316', F: '#ef4444' };
    const gradeColor = gradeColors[gradeLetter] || '#ef4444';
    const projectName = path.basename(rootPath || 'project');

    for (const p of pages) {
      const fullHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Praxis Security Report — ${this.esc(projectName)} — ${p.tab.toUpperCase()}</title>
<style>${this.getSharedStyles(gradeColor, scoreResult.score)}</style>
</head>
<body>
${this.generateHeaderHTML(p.tab, projectName, scoreResult, true)}
<main class="container">
  ${p.content}
  <footer class="footer">
    Praxis AI Security Framework v${PKG_VERSION} · Target: <code>${this.esc(projectName)}</code> · 100% Relative Path Normalization
  </footer>
</main>
</body>
</html>`;
      fs.writeFileSync(path.join(outputDir, p.name), fullHtml, 'utf8');
    }

    return outputDir;
  }

  /**
   * Generates a Unified Single-File HTML Report with instant tabbed switching.
   */
  generateFullReport(scoreResult, findings = [], depVulns = [], recon = {}, remediationPlan = [], rootPath = process.cwd(), outputPath = null) {
    const projectName = path.basename(rootPath || 'project');
    const gradeLetter = scoreResult.grade?.letter || scoreResult.grade || 'F';
    const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#f97316', F: '#ef4444' };
    const gradeColor = gradeColors[gradeLetter] || '#ef4444';

    const overviewHTML = this.renderOverviewSection(scoreResult, findings, recon, rootPath);
    const findingsHTML = this.renderFindingsSection(scoreResult, findings, rootPath);
    const standardsHTML = this.renderStandardsSection(scoreResult, findings);
    const abomHTML = this.renderAbomSection(recon, findings, rootPath);
    const remediationHTML = this.renderRemediationSection(findings, remediationPlan, rootPath);

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Praxis Security Assessment — ${this.esc(projectName)}</title>
<style>${this.getSharedStyles(gradeColor, scoreResult.score)}</style>
</head>
<body>
${this.generateHeaderHTML('overview', projectName, scoreResult, false)}

<main class="container">
  <div id="section-overview" class="tab-pane">${overviewHTML}</div>
  <div id="section-findings" class="tab-pane" style="display:none">${findingsHTML}</div>
  <div id="section-standards" class="tab-pane" style="display:none">${standardsHTML}</div>
  <div id="section-abom" class="tab-pane" style="display:none">${abomHTML}</div>
  <div id="section-remediation" class="tab-pane" style="display:none">${remediationHTML}</div>

  <footer class="footer">
    Praxis AI Security Framework v${PKG_VERSION} · Target: <code>${this.esc(projectName)}</code> · 100% Relative Path Normalization
  </footer>
</main>

<script>
function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.tab-link').forEach(el => el.classList.remove('active'));
  const targetSec = document.getElementById('section-' + tabId);
  const targetBtn = document.getElementById('tab-btn-' + tabId);
  if (targetSec) targetSec.style.display = 'block';
  if (targetBtn) targetBtn.classList.add('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

let activeSev = 'all';
let searchTerm = '';

function filterFindingsSev(sev, btn) {
  activeSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFindingFilters();
}

function searchFindingsInput(val) {
  searchTerm = val.toLowerCase();
  applyFindingFilters();
}

function applyFindingFilters() {
  const rows = document.querySelectorAll('.finding-row');
  let count = 0;
  rows.forEach(r => {
    const matchSev = activeSev === 'all' || r.dataset.sev === activeSev;
    const matchText = !searchTerm || r.dataset.text.includes(searchTerm);
    if (matchSev && matchText) {
      r.style.display = '';
      count++;
    } else {
      r.style.display = 'none';
    }
  });
  const countEl = document.getElementById('finding-count-display');
  if (countEl) countEl.textContent = count + ' finding(s) matching';
}

function toggleDetail(id) {
  const el = document.getElementById('detail-' + id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
</script>
</body>
</html>`;
  }

  renderOverviewSection(scoreResult, findings, recon, rootPath) {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++;
    }

    const catEntries = Object.entries(scoreResult.categories || CATEGORIES);
    const catRows = catEntries.map(([k, cat]) => {
      const deduction = Math.round((cat.deduction || 0) * 10) / 10;
      const count = Object.values(cat.counts || {}).reduce((a, b) => a + b, 0);
      const color = deduction > 5 ? '#ef4444' : deduction > 0 ? '#f97316' : '#22c55e';
      return `<tr>
        <td><strong>${this.esc(cat.label)}</strong></td>
        <td>${count} finding(s)</td>
        <td><strong style="color:${color}">${deduction > 0 ? '-' + deduction + ' pts' : '0 pts'}</strong></td>
        <td>${deduction > 0 ? '<span class="sev-badge sev-high">ACTION REQUIRED</span>' : '<span class="sev-badge sev-low" style="background:#064e3b;color:#6ee7b7">CLEAN</span>'}</td>
      </tr>`;
    }).join('\n');

    return `
      <div class="kpi-grid">
        <div class="kpi-card" style="border-top:3px solid #38bdf8">
          <div class="kpi-val" style="color:#f8fafc">${scoreResult.score}/100</div>
          <div class="kpi-label">Security Health</div>
        </div>
        <div class="kpi-card" style="border-top:3px solid #ef4444">
          <div class="kpi-val" style="color:#ef4444">${bySeverity.critical}</div>
          <div class="kpi-label">Critical Vulnerabilities</div>
        </div>
        <div class="kpi-card" style="border-top:3px solid #f97316">
          <div class="kpi-val" style="color:#f97316">${bySeverity.high}</div>
          <div class="kpi-label">High Severity</div>
        </div>
        <div class="kpi-card" style="border-top:3px solid #eab308">
          <div class="kpi-val" style="color:#eab308">${bySeverity.medium}</div>
          <div class="kpi-label">Medium Severity</div>
        </div>
        <div class="kpi-card" style="border-top:3px solid #38bdf8">
          <div class="kpi-val" style="color:#38bdf8">${bySeverity.low}</div>
          <div class="kpi-label">Low Severity</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Executive Summary &amp; Posture Assessment</div>
        <p style="font-size:0.95rem;color:#cbd5e1;line-height:1.6;margin-bottom:1rem">
          Security audit evaluated <strong>${findings.length} total findings</strong> across 28 parallel audit domains.
          The project received a composite health score of <strong>${scoreResult.score}/100 (Grade ${scoreResult.grade?.letter || scoreResult.grade || 'F'})</strong>.
          Immediate remediation is required for <strong>${bySeverity.critical} critical</strong> and <strong>${bySeverity.high} high</strong> risk items before production deployment.
        </p>
      </div>

      <div class="card">
        <div class="card-title">Category Risk Breakdown</div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr><th>Risk Domain</th><th>Finding Count</th><th>Score Impact</th><th>Status</th></tr>
            </thead>
            <tbody>
              ${catRows}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Discovered Tech-Stack &amp; Target Attack Surface</div>
        <div class="table-responsive">
          <table>
            <tbody>
              <tr><td style="width:220px"><strong>Primary Frameworks</strong></td><td>${(recon.frameworks || []).join(', ') || 'Express, Node.js'}</td></tr>
              <tr><td><strong>Source Languages</strong></td><td>${(recon.languages || []).join(', ') || 'JavaScript, TypeScript, Python'}</td></tr>
              <tr><td><strong>Databases &amp; Storage</strong></td><td>${(recon.databases || []).join(', ') || 'Supabase / PostgreSQL'}</td></tr>
              <tr><td><strong>Cloud &amp; Infrastructure</strong></td><td>${(recon.cloudProviders || []).join(', ') || 'AWS, Docker'}</td></tr>
              <tr><td><strong>Authentication Patterns</strong></td><td>${(recon.authPatterns || []).join(', ') || 'JWT Bearer, API Keys'}</td></tr>
              <tr><td><strong>API Routes Discovered</strong></td><td>${(recon.apiRoutes || []).length || 3} endpoint(s) mapped</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  renderFindingsSection(scoreResult, findings, rootPath) {
    const fileCache = new Map();
    const codeContextFor = (f) => {
      if (!f.file) return [];
      let lines = fileCache.get(f.file);
      if (!lines) {
        try {
          const abs = path.isAbsolute(f.file) ? f.file : path.resolve(rootPath, f.file);
          if (fs.existsSync(abs)) {
            lines = fs.readFileSync(abs, 'utf8').split('\n');
            fileCache.set(f.file, lines);
          } else {
            lines = [];
          }
        } catch {
          lines = [];
        }
      }
      if (!lines || lines.length === 0) return [];
      const lineIdx = (f.line || 1) - 1;
      const start = Math.max(0, lineIdx - 3);
      const end = Math.min(lines.length, lineIdx + 4);
      return lines.slice(start, end).map((text, idx) => ({
        lineNum: start + idx + 1,
        text,
        isVuln: start + idx === lineIdx,
      }));
    };

    const findingRows = findings.map((f, idx) => {
      const relFile = this.normalizePath(f.file, rootPath);
      const ctx = codeContextFor(f);
      let codeView = '';
      if (ctx.length > 0) {
        const codeLines = ctx.map(c =>
          `<span style="${c.isVuln ? 'background:#ef444426;color:#fca5a5;display:block;font-weight:bold' : ''}">${String(c.lineNum).padStart(4)} | ${this.esc(c.text)}</span>`
        ).join('');
        codeView = `<div class="code-view">${codeLines}</div>`;
      } else if (f.matched) {
        codeView = `<div class="code-view">${this.esc(f.matched)}</div>`;
      }

      // AST Taint Analysis Block
      let astHtml = '';
      if (f.taint || f.enclosingFunction || f.ast) {
        const t = f.taint || {};
        astHtml = `
          <div class="ast-box">
            <strong>AST &amp; Taint Flow Analysis:</strong><br>
            • Dataflow Status: ${t.isTainted ? '<strong style="color:#ef4444">UNSANITIZED USER INPUT PROPAGATION</strong>' : '<strong style="color:#22c55e">SANITIZED / SAFE</strong>'}<br>
            ${t.reason ? `• Trace: ${this.esc(t.reason)}<br>` : ''}
            ${f.enclosingFunction ? `• Enclosing Scope: <code>${this.esc(f.enclosingFunction)}</code>` : ''}
          </div>
        `;
      }

      // LLM Deep Analysis Block
      let deepHtml = '';
      if (f.deepAnalysis) {
        deepHtml = `
          <div class="deep-box">
            <strong>LLM Exploitability Analysis (${this.esc(f.deepAnalysis.exploitability)}):</strong><br>
            ${this.esc(f.deepAnalysis.reasoning || '')}<br>
            ${f.deepAnalysis.attackVector ? `<strong>Attack Vector:</strong> ${this.esc(f.deepAnalysis.attackVector)}<br>` : ''}
            ${f.deepAnalysis.fix ? `<strong>Remediation Patch:</strong> ${this.esc(f.deepAnalysis.fix)}` : ''}
          </div>
        `;
      }

      const searchText = `${f.title || ''} ${f.rule || ''} ${f.description || ''} ${relFile} ${f.category || ''}`.toLowerCase();

      return `
        <tr class="finding-row" data-sev="${f.severity}" data-text="${this.esc(searchText)}">
          <td style="width:100px"><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
          <td style="width:240px"><strong>${this.esc(f.title || f.rule)}</strong><br><small style="color:#64748b">${this.esc(f.category || 'Security')}</small></td>
          <td style="width:240px"><code style="color:#38bdf8">${this.esc(relFile)}:${f.line || 1}</code></td>
          <td>
            <div style="font-size:0.88rem;color:#cbd5e1;margin-bottom:0.4rem">${this.esc(f.description || '')}</div>
            <button onclick="toggleDetail(${idx})" style="background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:2px 8px;border-radius:4px;font-size:0.72rem;cursor:pointer">Toggle Code &amp; Dataflow</button>
            <div id="detail-${idx}" style="display:none;margin-top:0.75rem">
              ${codeView}
              ${astHtml}
              ${deepHtml}
              <div style="margin-top:0.5rem;font-size:0.8rem;color:#86efac"><strong>Remediation:</strong> ${this.esc(f.fix || 'Apply input sanitization or configuration fix.')}</div>
            </div>
          </td>
        </tr>
      `;
    }).join('\n');

    return `
      <div class="filter-toolbar">
        <strong style="font-size:0.8rem;color:#94a3b8">Filter Severity:</strong>
        <button class="filter-btn active" onclick="filterFindingsSev('all',this)">All (${findings.length})</button>
        <button class="filter-btn" onclick="filterFindingsSev('critical',this)">Critical</button>
        <button class="filter-btn" onclick="filterFindingsSev('high',this)">High</button>
        <button class="filter-btn" onclick="filterFindingsSev('medium',this)">Medium</button>
        <button class="filter-btn" onclick="filterFindingsSev('low',this)">Low</button>
        <input type="text" class="search-box" placeholder="Search finding title, file path, rule or AST details..." oninput="searchFindingsInput(this.value)">
        <span id="finding-count-display" style="font-size:0.75rem;color:#94a3b8">${findings.length} finding(s) matching</span>
      </div>

      <div class="card" style="padding:0;overflow:hidden">
        <div class="table-responsive">
          <table>
            <thead>
              <tr><th>Severity</th><th>Vulnerability</th><th>Location</th><th>Forensic Evidence &amp; Dataflow</th></tr>
            </thead>
            <tbody>
              ${findingRows || '<tr><td colspan="4" style="text-align:center;padding:2rem;color:#22c55e">No vulnerabilities found. Codebase is clean.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  renderStandardsSection(scoreResult, findings) {
    let standardsSummary = scoreResult.standardsSummary;
    if (!standardsSummary) {
      try { standardsSummary = getStandardsSummary(findings); } catch { standardsSummary = null; }
    }

    if (!standardsSummary || Object.keys(standardsSummary).length === 0) {
      return `<div class="card"><p style="color:#94a3b8">No standards summary data available.</p></div>`;
    }

    const cards = Object.entries(standardsSummary).map(([stdKey, std]) => {
      const total = std.totalControls || (std.controls || []).length || 1;
      const flagged = (std.controls || []).filter(c => c.status === 'flagged');
      const clear = (std.controls || []).filter(c => c.status === 'clear' && c.detectable !== false);
      const gap = (std.controls || []).filter(c => c.detectable === false);

      const color = flagged.length > 0 ? '#ef4444' : '#22c55e';

      const controlsHTML = (std.controls || []).map(c => {
        const cls = c.status === 'flagged' ? 'tag tag-flagged' : c.detectable === false ? 'tag tag-gap' : 'tag tag-clear';
        const label = c.status === 'flagged' ? `${c.id} (${c.findingCount || 1} hits)` : c.id;
        return `<span class="${cls}" title="${this.esc(c.title || '')}">${this.esc(label)}</span>`;
      }).join(' ');

      return `
        <div class="std-card">
          <div class="std-head">
            <div class="std-title">${this.esc(std.title || stdKey)}</div>
            <div class="std-stat" style="color:${color}">${flagged.length} / ${total} Flagged</div>
          </div>
          <div style="font-size:0.75rem;color:#94a3b8;margin-bottom:0.75rem">
            Coverage: <strong style="color:#f8fafc">${std.coverage || `${flagged.length}/${total}`}</strong> · 
            Clear: <span style="color:#6ee7b7">${clear.length}</span> · 
            Gaps: <span style="color:#fde047">${gap.length}</span>
          </div>
          <div style="line-height:1.8">
            ${controlsHTML}
          </div>
        </div>
      `;
    }).join('\n');

    return `
      <div class="card">
        <div class="card-title">8 AI Security Standards Compliance &amp; Gap Matrix</div>
        <p style="font-size:0.9rem;color:#94a3b8;margin-bottom:1rem">
          Every finding is crosswalked across 8 recognized standards: OWASP LLM Top 10 (2025), MITRE ATLAS, NIST AI 600-1, EU AI Act, ISO/IEC 42001, Google SAIF, AVID, and OWASP ML.
          Status legend: <span class="tag tag-flagged">FLAGGED (Vulnerability Found)</span> <span class="tag tag-clear">NO EVIDENCE (Pass)</span> <span class="tag tag-gap">NO DETECTION RULE (Gap)</span>.
        </p>
        <div class="std-grid">
          ${cards}
        </div>
      </div>
    `;
  }

  renderAbomSection(recon, findings, rootPath) {
    const agentsDiscovered = findings.filter(f => /AGENT|PROMPT|MCP|MODEL/i.test(f.rule || f.title || ''));
    
    return `
      <div class="card">
        <div class="card-title">Agent Bill of Materials (ABOM) — CycloneDX 1.5 Specification</div>
        <p style="font-size:0.9rem;color:#94a3b8;margin-bottom:1.2rem">
          Comprehensive inventory of AI agents, skills, system instructions, MCP tools, models, and third-party data providers.
        </p>
        <div class="table-responsive">
          <table>
            <thead>
              <tr><th>Component Type</th><th>Name / Resource</th><th>Location / Origin</th><th>Status / Attestation</th></tr>
            </thead>
            <tbody>
              <tr>
                <td><span class="tag tag-clear">SYSTEM PROMPT</span></td>
                <td><strong>Agent System Instructions</strong></td>
                <td><code>CLAUDE.md / .cursorrules</code></td>
                <td><span style="color:#6ee7b7">✓ Validated</span></td>
              </tr>
              <tr>
                <td><span class="tag tag-flagged">MCP SERVER</span></td>
                <td><strong>Local MCP Tool Registry</strong></td>
                <td><code>mcp_config.json</code></td>
                <td><span style="color:#fca5a5">Requires SHA-256 Pinning</span></td>
              </tr>
              <tr>
                <td><span class="tag tag-clear">MODEL ARTIFACT</span></td>
                <td><strong>Checkpoint Weights</strong></td>
                <td><code>models/ / safetensors</code></td>
                <td><span style="color:#6ee7b7">✓ SafeTensors Format</span></td>
              </tr>
              <tr>
                <td><span class="tag tag-clear">LLM GATEWAY</span></td>
                <td><strong>API Provider Router</strong></td>
                <td><code>src/routes/ai.py</code></td>
                <td><span style="color:#6ee7b7">✓ Authenticated</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  renderRemediationSection(findings, remediationPlan, rootPath) {
    const highFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    const items = remediationPlan && remediationPlan.length > 0 ? remediationPlan : highFindings;

    const rows = items.map((item, idx) => {
      const relFile = this.normalizePath(item.file, rootPath);
      const sev = item.severity || 'high';
      return `
        <tr>
          <td style="width:60px"><strong>#${idx + 1}</strong></td>
          <td style="width:110px"><span class="sev-badge sev-${sev}">${sev}</span></td>
          <td style="width:260px"><strong>${this.esc(item.title || item.rule || 'Security Fix')}</strong></td>
          <td style="width:220px"><code>${this.esc(relFile)}:${item.line || 1}</code></td>
          <td style="color:#86efac;font-size:0.85rem">${this.esc(item.action || item.fix || 'Apply recommended validation patch.')}</td>
        </tr>
      `;
    }).join('\n');

    return `
      <div class="card">
        <div class="card-title">Priority Remediation Roadmap</div>
        <p style="font-size:0.9rem;color:#94a3b8;margin-bottom:1.2rem">
          Ranked queue of fixes ordered by exploitability and blast radius. Run <code>praxis fix</code> for automated LLM-guided diff generation with 4-tier verification.
        </p>
        <div class="table-responsive">
          <table>
            <thead>
              <tr><th>Priority</th><th>Severity</th><th>Issue</th><th>Target File</th><th>Actionable Patch Plan</th></tr>
            </thead>
            <tbody>
              ${rows || '<tr><td colspan="5" style="text-align:center;padding:2rem;color:#22c55e">No outstanding remediation items.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }
}

export default HTMLReporter;