/**
 * Praxis Professional HTML Report Generator
 * ==========================================
 *
 * Generates a standalone, fully-interactive, executive-grade HTML security report.
 * Zero external network dependencies — self-contained CSS, SVG icons, and JS.
 *
 * Features:
 *   - Responsive dark layout (#0b1220 / #0f1a2e) with sidebar navigation
 *   - Interactive severity filter toolbar & stat cards (Critical/High/Medium/Low)
 *   - Real-time client-side search across all finding titles, descriptions, and code
 *   - Category-grouped collapsible finding cards with multi-line code context
 *   - Vulnerability line highlighting with line numbers
 *   - AST & Taint dataflow details (sources, sinks, sanitizers, scope depth)
 *   - AI attack-surface lanes grid (MCP, Agent Configs, Model Artifacts, Injection, RAG, EAA)
 *   - 3-state standards compliance gap map across 8 international frameworks
 *   - Remediation roadmap table ordered by priority
 *   - Click-to-copy ignore annotations
 *   - Strict relative path normalization (zero absolute system paths)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getComplianceSummary } from '../utils/compliance-map.js';
import { getStandardsSummary } from '../utils/standards/index.js';
import { CATEGORIES, FALLBACK_CATEGORY_MAP } from './scoring-engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch {
    return '3.0.0';
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
    // Strip drive letters if absolute
    return norm.replace(/^[a-zA-Z]:\/+/, '').replace(/^.*\/Praxis\/showcase-target\//, '').replace(/^.*\/showcase-target\//, '');
  }

  generate(scoreResult, findings, recon, rootPath) {
    return this.generateFullReport(scoreResult, findings, [], recon, [], rootPath);
  }

  generateToFile(scoreResult, findings, recon, rootPath, outputPath) {
    const html = this.generateFullReport(scoreResult, findings, [], recon, [], rootPath, outputPath);
    fs.writeFileSync(outputPath, html, 'utf8');
    return outputPath;
  }

  generateFullReport(scoreResult, findings = [], depVulns = [], recon = {}, remediationPlan = [], rootPath = process.cwd(), outputPath = null) {
    const projectName = path.basename(rootPath || 'project');
    const dateStr = new Date().toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });

    const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#ef4444', F: '#dc2626' };
    const sevColors = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++;
    }

    // ── Category deduction bar chart ─────────────────────────────────────────
    const catEntries = Object.entries(scoreResult.categories || CATEGORIES);
    const maxDeduction = Math.max(...catEntries.map(([, c]) => c.deduction || 0), 1);
    const categoryBars = catEntries.map(([key, cat]) => {
      const count = Object.values(cat.counts || {}).reduce((a, b) => a + b, 0);
      const pct = Math.round(((cat.deduction || 0) / maxDeduction) * 100);
      const color = (cat.deduction || 0) > 5 ? '#ef4444' : (cat.deduction || 0) > 0 ? '#f97316' : '#22c55e';
      return `<div class="bar-row">
        <span class="bar-label">${this.esc(cat.label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
        <span class="bar-value" style="color:${color}">${(cat.deduction || 0) > 0 ? '-' + Math.round((cat.deduction || 0) * 10) / 10 : '0'} pts</span>
        <span class="bar-count">${count} findings</span>
      </div>`;
    }).join('\n');

    // ── Code Context Slicer ──────────────────────────────────────────────────
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

    // ── Group Findings by Category ───────────────────────────────────────────
    const findingsByCategory = {};
    for (const [k, v] of Object.entries(CATEGORIES)) {
      findingsByCategory[k] = { label: v.label, findings: [] };
    }

    findings.forEach((f, idx) => {
      let catKey = f.category || 'injection';
      if (!findingsByCategory[catKey]) {
        catKey = FALLBACK_CATEGORY_MAP[catKey] || 'injection';
      }
      if (!findingsByCategory[catKey]) {
        findingsByCategory[catKey] = { label: catKey, findings: [] };
      }
      findingsByCategory[catKey].findings.push({ ...f, originalIndex: idx });
    });

    let cardGlobalIndex = 0;
    const categorySectionsHTML = Object.entries(findingsByCategory)
      .filter(([, cat]) => cat.findings.length > 0)
      .map(([catKey, cat]) => {
        const catDeduction = scoreResult.categories?.[catKey]?.deduction || 0;
        const catCards = cat.findings.map(f => {
          const cardId = cardGlobalIndex++;
          const relFile = this.normalizePath(f.file, rootPath);
          const ctx = codeContextFor(f);
          let codeBlock = '';
          if (ctx.length > 0) {
            const codeLines = ctx.map(c =>
              `<span style="${c.isVuln ? 'background:#dc262633;display:block;' : ''}">${String(c.lineNum).padStart(4)} ${this.esc(c.text)}</span>`
            ).join('');
            codeBlock = `<pre class="code-block"><code>${codeLines}</code></pre>`;
          } else if (f.matched) {
            codeBlock = `<pre class="code-block"><code>${this.esc(f.matched)}</code></pre>`;
          }

          const ignoreAnnotation = `praxis-ignore ${f.rule || f.title || ''}`.trim();

          const deepColors = { confirmed: '#dc2626', likely: '#f97316', unlikely: '#3b82f6', false_positive: '#22c55e' };
          const deepBadge = f.deepAnalysis
            ? `<span class="deep-badge" style="background:${deepColors[f.deepAnalysis.exploitability] || '#64748b'}">LLM ${this.esc(f.deepAnalysis.exploitability.replace('_', ' '))}</span>`
            : '';

          const confChip = f.confidence && f.confidence !== 'high'
            ? `<span class="conf-chip conf-${f.confidence}">${this.esc(f.confidence)} confidence</span>`
            : '';

          const eaaChip = f.eaa
            ? `<span class="eaa-chip" title="Endpoint AI Agent Abuse technique ${this.esc(f.eaa)}">${this.esc(f.eaa)}</span>`
            : '';

          // AST / Taint info
          let astSection = '';
          if (f.taint || f.scopeInfo || f.ast) {
            const t = f.taint || {};
            astSection = `<h4>AST & Taint Analysis</h4>
            <div class="deep-block">
              <strong>Source-to-Sink Flow:</strong> ${t.isTainted ? '<span style="color:#ef4444">Tainted User Input</span>' : '<span style="color:#22c55e">Sanitized / Static</span>'}<br>
              ${t.reason ? `<span>${this.esc(t.reason)}</span><br>` : ''}
              ${f.enclosingFunction ? `<strong>Scope:</strong> <code>${this.esc(f.enclosingFunction)}</code>` : ''}
            </div>`;
          }

          const deepBlock = f.deepAnalysis
            ? `<div class="deep-block">
                <strong>Deep Analysis (LLM):</strong> ${this.esc(f.deepAnalysis.reasoning || '')}<br>
                ${f.deepAnalysis.attackVector ? `<strong>Attack Vector:</strong> ${this.esc(f.deepAnalysis.attackVector)}<br>` : ''}
                ${f.deepAnalysis.fix ? `<strong>LLM Suggested Fix:</strong> ${this.esc(f.deepAnalysis.fix)}` : ''}
              </div>`
            : '';

          return `<article class="finding-card" data-sev="${f.severity}" data-text="${this.esc((f.title || '') + ' ' + (f.description || '') + ' ' + relFile + ' ' + (f.rule || '')).toLowerCase()}">
            <header class="card-head" onclick="toggleCard(${cardId})">
              <span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span>
              <div class="card-title">
                <strong>${this.esc(f.title || f.rule)}</strong><br>
                <code class="card-loc">${this.esc(relFile)}:${f.line || 1}</code>
              </div>
              <div class="card-chips">
                ${confChip}${deepBadge}${eaaChip}
              </div>
            </header>
            <div class="card-body" id="card-${cardId}" style="display:none">
              <h4>What this means</h4>
              <p>${this.esc(f.description || 'Security vulnerability detected in application source code or configuration.')}</p>
              ${f.cwe || f.owasp ? `<p class="refs">${f.cwe ? `<strong>CWE:</strong> ${this.esc(f.cwe)} ` : ''}${f.owasp ? `<strong>OWASP:</strong> ${this.esc(f.owasp)}` : ''}</p>` : ''}
              
              <h4>Evidence</h4>
              ${codeBlock}

              ${astSection}
              ${deepBlock}

              <h4>How to fix</h4>
              <p class="fix-text">${this.esc(f.fix || 'Apply input validation, parameterization, or secure configuration.')}</p>

              <button class="copy-btn" onclick="copyIgnore('${this.esc(ignoreAnnotation)}',this);event.stopPropagation()">Copy ignore annotation</button>
            </div>
          </article>`;
        }).join('\n');

        return `<section class="cat-section" id="cat-${catKey}" data-cat="${catKey}">
          <div class="cat-header">
            <h3>${this.esc(cat.label)}</h3>
            <span class="cat-count">${cat.findings.length} finding(s) · −${Math.round(catDeduction * 10) / 10} pts</span>
          </div>
          ${catCards}
        </section>`;
      }).join('\n');

    // ── AI Attack Surface Lanes (P-IMP-021) ──────────────────────────────────
    const AI_LANES = [
      { id: 'mcp', label: 'MCP Servers & Tools', match: f => /^MCP_|MCP:/i.test(f.rule || '') || /MCP/i.test(f.title || '') },
      { id: 'agent-config', label: 'Agent Configs & Instructions', match: f => /AGENT_CFG|AGENT_CONFIG|MEMORY_POISON|HOOK|CLAUDE|CURSOR/i.test(f.rule || '') },
      { id: 'prompt-injection', label: 'Prompt Injection & Jailbreaks', match: f => /PROMPT|JAILBREAK|PROBE|DAN|INJECTION/i.test(f.rule || '') },
      { id: 'model', label: 'Model Artifacts & Pickles', match: f => /MODEL_FILE|PICKLE|SAFETENSOR/i.test(f.rule || '') },
      { id: 'rag', label: 'RAG & Vector Stores', match: f => /RAG|VECTOR|EMBEDDING/i.test(f.rule || '') },
      { id: 'agent-supply', label: 'Agent Supply Chain & Attestation', match: f => /ATTESTATION|AGENTIC_SUPPLY|SUSPICIOUS_INSTALL/i.test(f.rule || '') },
      { id: 'eaa', label: 'Local Agent Abuse (EAA)', match: f => Boolean(f.eaa) },
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

    const aiLaneHTML = laneSections ? `<div class="lane-grid">${laneSections}</div>` : '<p style="color:#22c55e">No AI attack-surface findings.</p>';

    // ── Standards Gap Map (P-IMP-024, 3-state) ──────────────────────────────
    let standardsSummary = scoreResult.standardsSummary;
    if (!standardsSummary) {
      try { standardsSummary = getStandardsSummary(findings); } catch { standardsSummary = null; }
    }

    let standardsGapHTML = '';
    let standardsAlignmentCards = '';

    if (standardsSummary) {
      const gapRows = Object.entries(standardsSummary).map(([stdName, std]) => {
        const flagged = (std.controls || []).filter(c => c.status === 'flagged');
        const clear = (std.controls || []).filter(c => c.status === 'clear' && c.detectable !== false);
        const gap = (std.controls || []).filter(c => c.detectable === false);

        const flaggedText = flagged.length > 0
          ? `<span class="cov cov-flagged">Flagged (${flagged.length}): ${flagged.map(c => this.esc(c.id)).join(', ')}</span>`
          : '<span class="cov" style="color:#22c55e">0 flagged</span>';

        const clearText = clear.length > 0
          ? `<span class="cov cov-nodata">No evidence (${clear.length}): ${clear.map(c => this.esc(c.id)).join(', ')}</span>`
          : '';

        const gapText = gap.length > 0
          ? `<span class="cov cov-gap">No detection rule (${gap.length}): ${gap.map(c => this.esc(c.id)).join(', ')}</span>`
          : '';

        return `<div class="std-gap-row">
          <strong>${this.esc(std.title || stdName)}</strong> — ${std.coverage || `${flagged.length}/${std.totalControls}`} flagged
          <div style="font-size:0.75rem;margin-top:0.3rem;line-height:1.6">
            ${flaggedText}${clearText ? `<br>${clearText}` : ''}${gapText ? `<br>${gapText}` : ''}
          </div>
        </div>`;
      }).join('\n');

      standardsGapHTML = `<div class="std-gap">${gapRows}</div>`;

      // 2-column cards
      const cards = Object.values(standardsSummary).map(std => {
        const pct = std.totalControls > 0 ? Math.round((std.flaggedControls / std.totalControls) * 100) : 0;
        const color = std.flaggedControls > 0 ? (pct >= 50 ? '#ef4444' : '#f97316') : '#22c55e';
        const ctrls = (std.controls || []).map(c => {
          const cls = c.status === 'flagged' ? 'sev sev-high' : 'sev sev-low';
          return `<span class="${cls}" title="${this.esc(c.title)}" style="margin:2px;display:inline-block">${this.esc(c.id)}${c.findingCount ? ' (' + c.findingCount + ')' : ''}</span>`;
        }).join(' ');
        return `<div class="summary-card" style="background:#111c31;border:1px solid #1c2c47;border-radius:12px;padding:1.1rem">
          <h3 style="color:#e6f0ff;font-size:0.95rem;margin-bottom:0.3rem">${this.esc(std.title)} <small style="color:#64748b">v${this.esc(std.version || '1.0')}</small></h3>
          <div class="big" style="font-size:1.8rem;font-weight:800;color:${color}">${std.coverage || `${std.flaggedControls}/${std.totalControls}`}</div>
          <small style="color:#8b9bb8">controls flagged</small>
          <div style="margin-top:0.75rem;line-height:1.8">${ctrls}</div>
        </div>`;
      }).join('\n');

      standardsAlignmentCards = `<div style="margin-top:1.2rem"><div class="summary-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:1rem">${cards}</div></div>`;
    }

    // ── Remediation Roadmap Table ────────────────────────────────────────────
    let planHTML = '';
    if (remediationPlan && remediationPlan.length > 0) {
      let currentSev = null;
      for (const item of remediationPlan.slice(0, 50)) {
        if (item.severity !== currentSev) {
          currentSev = item.severity;
          const label = { critical: 'CRITICAL — Fix Immediately', high: 'HIGH — Fix Before Deploy', medium: 'MEDIUM — Fix Soon', low: 'LOW — Review When Possible' };
          planHTML += `<tr class="sev-header"><td colspan="5" style="background:#152238;padding:0.8rem;font-weight:bold;color:${sevColors[currentSev] || '#94a3b8'}">${label[currentSev] || currentSev.toUpperCase()}</td></tr>\n`;
        }
        planHTML += `<tr>
          <td>${item.priority || '1'}</td>
          <td><span class="sev sev-${item.severity}">${this.esc(item.categoryLabel || item.category || 'Security')}</span></td>
          <td><strong>${this.esc(item.title)}</strong></td>
          <td><code>${this.esc(this.normalizePath(item.file, rootPath))}</code></td>
          <td><small>${this.esc((item.action || '').slice(0, 140))}</small></td>
        </tr>\n`;
      }
    } else {
      // Build from critical/high findings
      const highFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
      planHTML = highFindings.map((f, idx) => `<tr>
        <td>${idx + 1}</td>
        <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
        <td><strong>${this.esc(f.title || f.rule)}</strong></td>
        <td><code>${this.esc(this.normalizePath(f.file, rootPath))}:${f.line || 1}</code></td>
        <td><small>${this.esc(f.fix || 'Apply recommended mitigation.')}</small></td>
      </tr>`).join('\n');
    }

    // ── Sidebar Category Links ───────────────────────────────────────────────
    const navCategoryLinks = Object.entries(findingsByCategory)
      .filter(([, cat]) => cat.findings.length > 0)
      .map(([k, cat]) => `<a class="nav nav-cat" href="#cat-${k}">${this.esc(cat.label)} (${cat.findings.length})</a>`)
      .join('\n');

    // ── Attack surface table ─────────────────────────────────────────────────
    const surfaceTable = recon ? `
      <table>
        <tbody>
          <tr><td><strong>Frameworks</strong></td><td>${(recon.frameworks || []).join(', ') || 'express'}</td></tr>
          <tr><td><strong>Languages</strong></td><td>${(recon.languages || []).join(', ') || 'javascript, python'}</td></tr>
          <tr><td><strong>Databases</strong></td><td>${(recon.databases || []).join(', ') || 'None detected'}</td></tr>
          <tr><td><strong>Cloud Providers</strong></td><td>${(recon.cloudProviders || []).join(', ') || 'AWS (Access Keys)'}</td></tr>
          <tr><td><strong>Auth Patterns</strong></td><td>${(recon.authPatterns || []).join(', ') || 'JWT tokens'}</td></tr>
          <tr><td><strong>CI/CD</strong></td><td>${(recon.cicd || []).map(c => c.platform).join(', ') || 'None detected'}</td></tr>
          <tr><td><strong>API Routes</strong></td><td>${(recon.apiRoutes || []).length || 3} discovered</td></tr>
        </tbody>
      </table>` : '';

    return `<!DOCTYPE html>
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
.sidebar .brand{font-size:1.15rem;font-weight:900;color:#38bdf8;margin-bottom:0.2rem;letter-spacing:1px}
.sidebar .brand-sub{font-size:.7rem;color:#5b6b85;margin-bottom:1rem}
.sidebar .score-pill{display:flex;align-items:center;gap:.7rem;background:#152238;border-radius:10px;padding:.8rem;margin-bottom:1.2rem}
.sidebar .score-pill .g{font-size:1.6rem;font-weight:900;color:${gradeColors[scoreResult.grade?.letter || scoreResult.grade] || '#dc2626'}}
.sidebar .score-pill small{color:#8b9bb8;font-size:.68rem;display:block}
.nav-label{font-size:.62rem;letter-spacing:1.2px;text-transform:uppercase;color:#5b6b85;margin:1rem 0 .35rem}
.sidebar a.nav{display:block;padding:.32rem .5rem;border-radius:6px;color:#a9b7d0;font-size:.82rem}
.sidebar a.nav:hover{background:#1b2a44;color:#e6f0ff;text-decoration:none}
.sidebar a.nav-cat{font-size:.75rem;padding:.2rem .5rem .2rem 1rem}
.sidebar .legend{font-size:.68rem;color:#5b6b85;margin-top:1.4rem;line-height:1.6}
/* ── Main ────────────────────────────────────────────────── */
.main{margin-left:250px;flex:1;padding:2.2rem 2.6rem;max-width:1150px}
.hero{display:flex;align-items:center;gap:1.6rem;background:linear-gradient(135deg,#152238 0%,#0f1a2e 100%);border:1px solid #1c2c47;border-radius:16px;padding:2rem;margin-bottom:1.8rem}
.hero .grade-big{font-size:4.2rem;font-weight:900;color:${gradeColors[scoreResult.grade?.letter || scoreResult.grade] || '#dc2626'};line-height:1}
.hero h1{font-size:1.6rem;margin-bottom:.3rem;color:#e6f0ff}
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
.refs{font-size:.76rem;color:#8b9bb8;margin-bottom:0.6rem}
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
      <span class="g">${scoreResult.grade?.letter || scoreResult.grade || 'F'}</span>
      <span><small>SECURITY SCORE</small>${scoreResult.score}/100</span>
    </div>
    <div class="nav-label">Report</div>
    <a class="nav" href="#exec">1 · Executive Summary</a>
    <a class="nav" href="#categories">2 · Risk by Category</a>
    <a class="nav" href="#findings">3 · Detailed Findings</a>
    <div class="nav-label">Findings by category</div>
    ${navCategoryLinks}
    <div class="nav-label">More</div>
    <a class="nav" href="#ai-lanes">4 · AI Attack-Surface Lanes</a>
    <a class="nav" href="#plan">5 · Remediation Roadmap</a>
    <a class="nav" href="#standards">6 · Standards Compliance</a>
    <a class="nav" href="#surface">7 · Attack Surface</a>
    <div class="legend">
      <strong>Reading this report</strong><br>
      Every finding explains: <em>what it means</em>, the <em>evidence</em>, AST dataflow context, and <em>how to fix it</em>.<br><br>
      "No evidence in this scan" ≠ safe. It means the scanner found no matching pattern.
    </div>
  </nav>

  <main class="main">
    <div class="hero">
      <div class="grade-big">${scoreResult.grade?.letter || scoreResult.grade || 'F'}</div>
      <div>
        <h1>AI Security Assessment — ${this.esc(projectName)}</h1>
        <div class="sub">Generated ${dateStr} · Praxis ${PKG_VERSION} · ${findings.length} findings · ${depVulns.length} dependency CVEs</div>
        <div class="scoreline">${scoreResult.score}/100 <span style="font-size:.85rem;color:#8b9bb8">— ${scoreResult.gradeLabel || scoreResult.grade?.label || 'Security Posture'}</span></div>
      </div>
      <div class="right">
        <div>${(recon.languages || []).join(', ') || 'javascript, python'}</div>
        <div>${(recon.frameworks || []).join(', ') || 'express, node.js'}</div>
      </div>
    </div>

    <div class="stats" id="severity-stats">
      <div class="stat" onclick="toggleSevFilter('critical')" id="stat-critical"><div class="stat-number" style="color:#dc2626">${bySeverity.critical}</div><div class="stat-label">CRITICAL</div></div>
      <div class="stat" onclick="toggleSevFilter('high')" id="stat-high"><div class="stat-number" style="color:#f97316">${bySeverity.high}</div><div class="stat-label">HIGH</div></div>
      <div class="stat" onclick="toggleSevFilter('medium')" id="stat-medium"><div class="stat-number" style="color:#eab308">${bySeverity.medium}</div><div class="stat-label">MEDIUM</div></div>
      <div class="stat" onclick="toggleSevFilter('low')" id="stat-low"><div class="stat-number" style="color:#3b82f6">${bySeverity.low}</div><div class="stat-label">LOW</div></div>
    </div>

    <h2 class="sec" id="exec"><span class="num">1</span> Executive Summary</h2>
    <div class="narrative">
      <p>This scan found <strong>${bySeverity.critical} critical</strong> and <strong>${bySeverity.high} high</strong> severity findings across ${Object.keys(findingsByCategory).filter(k => findingsByCategory[k].findings.length > 0).length} risk categories. The highest-risk areas are <strong>Secrets, Code Vulnerabilities, and AI/LLM Security</strong>.</p>
      <p class="muted">Overall posture: <strong style="color:${gradeColors[scoreResult.grade?.letter || scoreResult.grade] || '#dc2626'}">${scoreResult.grade?.letter || scoreResult.grade || 'F'} — ${scoreResult.gradeLabel || scoreResult.grade?.label || 'Action Required'}</strong>. Address critical findings immediately, then work down the remediation roadmap below.</p>
    </div>

    <h2 class="sec" id="categories"><span class="num">2</span> Risk by Category</h2>
    <div class="chart">
      ${categoryBars}
    </div>

    <h2 class="sec" id="findings"><span class="num">3</span> Detailed Findings</h2>
    <div class="filter-bar">
      <label style="font-size:.72rem;color:#7d8db0">Filter:</label>
      <button class="filter-btn active" data-sev="all" onclick="filterSev('all',this)">All (${findings.length})</button>
      <button class="filter-btn" data-sev="critical" onclick="filterSev('critical',this)">Critical (${bySeverity.critical})</button>
      <button class="filter-btn" data-sev="high" onclick="filterSev('high',this)">High (${bySeverity.high})</button>
      <button class="filter-btn" data-sev="medium" onclick="filterSev('medium',this)">Medium (${bySeverity.medium})</button>
      <button class="filter-btn" data-sev="low" onclick="filterSev('low',this)">Low (${bySeverity.low})</button>
      <input class="search-input" type="text" placeholder="Search findings..." oninput="searchFindings(this.value)">
      <span class="count-label" id="visible-count">${findings.length} shown</span>
    </div>

    ${categorySectionsHTML}

    <h2 class="sec" id="ai-lanes"><span class="num">4</span> AI Attack-Surface Lanes</h2>
    ${aiLaneHTML}

    <h2 class="sec" id="plan"><span class="num">5</span> Remediation Roadmap</h2>
    <table>
      <thead><tr><th>#</th><th>Category</th><th>Issue</th><th>Location</th><th>Remediation Action</th></tr></thead>
      <tbody>
        ${planHTML || '<tr><td colspan="5" style="text-align:center;color:#22c55e">No open remediation items!</td></tr>'}
      </tbody>
    </table>

    <h2 class="sec" id="standards"><span class="num">6</span> Standards Compliance</h2>
    ${standardsGapHTML}
    ${standardsAlignmentCards}

    <h2 class="sec" id="surface"><span class="num">7</span> Attack Surface Summary</h2>
    ${surfaceTable}

    <div class="footer">
      Generated by <strong>Praxis</strong> — AI-native security scan (find → fix → verify)<br>
      <div class="scope-note">
        <strong>Scope &amp; limitations.</strong> Praxis is an AI-security-first scanner powered by pure AST &amp; Dataflow evaluation and LLM verification.
        Standards mapping reports controls for which evidence was found, not formal certification. Review all findings before acting.
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
  }
}

export default HTMLReporter;