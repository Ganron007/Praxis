/**
 * Team Report Command
 * ====================
 *
 * Converts raw Hermes Agent team output into a professional Praxis report.
 * Strips ANSI codes and terminal chrome, parses structured FINDING: lines,
 * and renders everything through Praxis's HTML reporter.
 *
 * USAGE:
 *   praxis team-report                     Read from stdin (pipe Hermes output)
 *   praxis team-report output.txt          Read from file
 *   praxis team-report output.txt --html   Save as HTML
 *   praxis team-report output.txt --json   JSON output
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import * as output from '../utils/output.js';
import { printBanner } from '../utils/output.js';
import {
  SEVERITY_COLORS,
  baseStyles,
  countBySeverity,
  documentShell,
  esc,
  severityBadge,
} from '../core/output/html-theme.js';

// =============================================================================
// ANSI + TERMINAL NOISE STRIPPING
// =============================================================================

function stripAnsi(str) {
  // Remove all ANSI escape sequences (colors, cursor moves, clears, etc.)
  /* eslint-disable no-control-regex -- intentional: strips ANSI/terminal escape sequences from captured CLI output */
  return str
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x9b[0-9;]*[A-Za-z]/g, '');
  /* eslint-enable no-control-regex */
}

function stripHermesChrome(text) {
  const lines = text.split('\n');
  const cleaned = [];
  let inSplash = false;

  for (const line of lines) {
    const t = line.trim();

    // Skip the Hermes splash box (╭─ ... ─╮ ... ╰─ ... ─╯)
    if (t.startsWith('╭─') || t.startsWith('╰─')) { inSplash = !inSplash; continue; }
    if (inSplash) continue;

    // Skip raw system prompt instructions leaked into output.
    // Template lines carry '...' placeholders; real findings parse as JSON.
    if (t.startsWith('EXACTLY this format')) continue;
    if (t.startsWith('FINDING: {"severity"') && t.includes('...')) continue;
    if (t.match(/^─{10,}$/)) continue;

    // Skip Hermes warning lines
    if (t.startsWith('⚠') && t.includes('hermes')) continue;
    if (t.startsWith('⚠') && t.includes('OPENROUTER')) continue;
    if (t.startsWith('⚠') && (t.includes('API call failed') || t.includes('credits'))) continue;
    if (t.startsWith('⏱') || t.startsWith('❌')) continue;

    // Skip terminal screen-clear sequences
    if (t === '[2J' || t === '[H' || t === '[2J[H') continue;

    cleaned.push(line);
  }

  return cleaned.join('\n');
}

// =============================================================================
// FINDING PARSER
// =============================================================================

function parseFindings(text) {
  const findings = [];
  const findingRegex = /^FINDING:\s*(\{.+\})\s*$/gm;
  let match;

  while ((match = findingRegex.exec(text)) !== null) {
    try {
      const f = JSON.parse(match[1]);
      if (f.severity && f.title) findings.push(f);
    } catch { /* skip malformed */ }
  }

  return findings;
}

// =============================================================================
// AGENT SECTION PARSER
// =============================================================================

function parseAgentSections(text) {
  const sections = [];
  // Matches: ### Agent Name (Role) — N finding(s)
  const sectionRegex = /###\s+(.+?)\s*(?:\(([^)]+)\))?\s*[—–-]+\s*(\d+)\s*finding/gi;
  let match;

  while ((match = sectionRegex.exec(text)) !== null) {
    sections.push({
      name: match[1].trim(),
      role: match[2]?.trim() || '',
      count: parseInt(match[3], 10),
    });
  }

  // Also collect bullet findings under each section
  const bulletRegex = /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)\s*[—–-]+\s*(.+)/gi;
  const bullets = [];
  while ((match = bulletRegex.exec(text)) !== null) {
    bullets.push({
      severity: match[1].toLowerCase(),
      title: match[2].trim(),
      location: match[3].trim(),
    });
  }

  return { sections, bullets };
}

// =============================================================================
// SYNTHESIS PARSER
// =============================================================================

function parseSynthesis(text) {
  // Extract the Hermes synthesis block (inside ╭─ ⚕ Hermes ─╮ ... ╰─╯)
  // After stripping chrome, look for the summary block
  const lines = text.split('\n');
  const synthesisLines = [];
  let capturing = false;

  for (const line of lines) {
    const t = line.trim();

    // The synthesis is the content after the agent section summary and before errors
    if (t.match(/^Overall risk posture:/i)) { capturing = true; }
    if (capturing) {
      if (t.startsWith('⚠') || t.startsWith('❌') || t.startsWith('⏱')) break;
      synthesisLines.push(line);
    }
  }

  // Also look for risk posture statement
  const riskMatch = text.match(/Overall risk posture:\s*(.+)/i);
  const riskPosture = riskMatch ? riskMatch[1].trim() : null;

  // Parse roadmap sections
  const immediateMatch = text.match(/\*\*Immediate[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);
  const shortTermMatch = text.match(/\*\*Short-term[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);
  const longTermMatch  = text.match(/\*\*Long-term[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);

  return {
    riskPosture,
    synthesis: synthesisLines.join('\n').trim(),
    roadmap: {
      immediate: immediateMatch?.[1]?.trim() || null,
      shortTerm: shortTermMatch?.[1]?.trim() || null,
      longTerm:  longTermMatch?.[1]?.trim()  || null,
    },
  };
}

// =============================================================================
// TARGET PARSER
// =============================================================================

function parseTarget(text) {
  const match = text.match(/assessments?\s+of\s+\*\*([^*]+)\*\*/i);
  return match ? match[1].trim() : 'Unknown Target';
}

// =============================================================================
// HTML RENDERER
// =============================================================================

function generateHTML(target, findings, agentSections, synthesis, bullets) {
  const date = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });

  // Merge FINDING: JSON lines with bullet-parsed findings (bullets are fallback)
  const allFindings = findings.length > 0 ? findings : bullets.map(b => ({
    severity: b.severity,
    title: b.title,
    location: b.location,
    remediation: '',
  }));

  const sevCounts = countBySeverity(allFindings);

  const riskColor = (rp) => {
    if (!rp) return '#94a3b8';
    const lc = String(rp).toLowerCase();
    if (lc.includes('critical')) return SEVERITY_COLORS.critical;
    if (lc.includes('high')) return SEVERITY_COLORS.high;
    if (lc.includes('medium')) return SEVERITY_COLORS.medium;
    return '#22c55e';
  };

  const findingRows = allFindings.map(f => `
    <tr>
      <td>${severityBadge(f.severity)}</td>
      <td><code>${esc(f.location) || '—'}</code></td>
      <td><strong>${esc(f.title)}</strong>${f.cve ? `<br><small>CVE: ${esc(f.cve)}</small>` : ''}</td>
      <td><small>${esc(f.remediation) || '—'}</small></td>
    </tr>`).join('');

  const agentRows = agentSections.sections.map(s => `
    <tr>
      <td>${esc(s.name)}</td>
      <td><code>${esc(s.role) || '—'}</code></td>
      <td style="color:${s.count > 0 ? SEVERITY_COLORS.high : '#22c55e'}">${esc(s.count)}</td>
    </tr>`).join('');

  const roadmap = synthesis.roadmap;
  const roadmapRow = (label, text, color) => text
    ? `<tr><td style="color:${color};white-space:nowrap;font-weight:600">${label}</td><td>${esc(text)}</td></tr>`
    : '';
  const roadmapHTML = (roadmap.immediate || roadmap.shortTerm || roadmap.longTerm) ? `
    <h2>Remediation Roadmap</h2>
    <table>
      <tbody>
        ${roadmapRow('⚡ Immediate (24–48h)', roadmap.immediate, SEVERITY_COLORS.critical)}
        ${roadmapRow('📅 Short-term (1–2 weeks)', roadmap.shortTerm, SEVERITY_COLORS.high)}
        ${roadmapRow('🏗 Long-term (1–3 months)', roadmap.longTerm, SEVERITY_COLORS.medium)}
      </tbody>
    </table>` : '';

  return documentShell({
    title: `Praxis Team Report — ${target}`,
    styles: baseStyles() + `
      .header{display:flex;align-items:center;gap:1rem;margin-bottom:2rem}
      .logo{font-size:1.5rem;font-weight:800;color:#38bdf8;letter-spacing:-1px}
      .badge{background:#1e293b;padding:3px 10px;border-radius:20px;font-size:0.75rem;color:#94a3b8;border:1px solid #334155}
      .meta{color:#64748b;font-size:0.85rem;margin-bottom:2rem}
      .risk-card{background:#0d1527;border:1px solid #1e293b;border-radius:12px;padding:1.5rem 2rem;margin-bottom:2rem;display:flex;align-items:center;gap:1.5rem}
      .risk-label{font-size:0.75rem;text-transform:uppercase;color:#64748b;margin-bottom:0.25rem}
      .risk-value{font-size:1.5rem;font-weight:700}
      .risk-desc{color:#94a3b8;font-size:0.9rem;flex:1}
      .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:0.75rem;margin-bottom:2rem}
      .stat{background:#0d1527;padding:1.25rem;border-radius:8px;text-align:center;border:1px solid #1e293b}
      .stat-number{font-size:2rem;font-weight:bold}
      .stat-label{color:#64748b;font-size:0.75rem;margin-top:0.25rem;text-transform:uppercase}
      .powered{color:#38bdf8}
      @media(max-width:1024px){.stats{grid-template-columns:repeat(2,1fr)}}
    `,
    body: `<div class="container">

  <div class="header">
    <span class="logo">Praxis</span>
    <span class="badge">Team Security Report</span>
    <span class="badge">Powered by Hermes Agent</span>
  </div>

  <h1>${esc(target)}</h1>
  <p class="meta">Generated ${esc(date)} · ${allFindings.length} finding${allFindings.length !== 1 ? 's' : ''} · ${agentSections.sections.length} agent${agentSections.sections.length !== 1 ? 's' : ''}</p>

  ${synthesis.riskPosture ? `
  <div class="risk-card">
    <div>
      <div class="risk-label">Overall Risk Posture</div>
      <div class="risk-value" style="color:${riskColor(synthesis.riskPosture)}">${esc(String(synthesis.riskPosture).split('—')[0].trim())}</div>
    </div>
    <div class="risk-desc">${esc(synthesis.riskPosture.includes('—') ? String(synthesis.riskPosture).split('—').slice(1).join('—').trim() : '')}</div>
  </div>` : ''}

  <div class="stats">
    <div class="stat"><div class="stat-number" style="color:${SEVERITY_COLORS.critical}">${sevCounts.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-number" style="color:${SEVERITY_COLORS.high}">${sevCounts.high}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-number" style="color:${SEVERITY_COLORS.medium}">${sevCounts.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-number" style="color:${SEVERITY_COLORS.low}">${sevCounts.low}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-number" style="color:${SEVERITY_COLORS.info}">${sevCounts.info}</div><div class="stat-label">Info</div></div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Remediation</th></tr></thead>
    <tbody>${findingRows || '<tr><td colspan="4" class="empty-state">No findings — clean!</td></tr>'}</tbody>
  </table>

  ${agentSections.sections.length > 0 ? `
  <h2>Agent Team Summary</h2>
  <table>
    <thead><tr><th>Agent</th><th>Role</th><th>Findings</th></tr></thead>
    <tbody>${agentRows}</tbody>
  </table>` : ''}

  ${roadmapHTML}

  <div class="footer">
    Secured by <span class="powered">Praxis</span> · <code>npx praxis red-team .</code>
  </div>
</div>`,
  });
}

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function teamReportCommand(inputFile, options = {}) {
  let raw;

  if (inputFile) {
    if (!fs.existsSync(inputFile)) {
      output.error(`File not found: ${inputFile}`);
      process.exit(1);
    }
    raw = fs.readFileSync(inputFile, 'utf-8');
  } else {
    // Read from stdin
    raw = fs.readFileSync('/dev/stdin', 'utf-8');
  }

  // Clean the input
  const stripped = stripAnsi(raw);
  const cleaned  = stripHermesChrome(stripped);

  // Parse
  const target       = parseTarget(stripped);
  const findings     = parseFindings(cleaned);
  const agentSections = parseAgentSections(cleaned);
  const synthesis    = parseSynthesis(cleaned);

  const allFindings = findings.length > 0 ? findings : agentSections.bullets.map(b => ({
    severity: b.severity,
    title: b.title,
    location: b.location,
    remediation: '',
  }));

  if (options.json) {
    console.log(JSON.stringify({ target, findings: allFindings, agentSections: agentSections.sections, synthesis }, null, 2));
    return;
  }

  if (options.html !== undefined) {
    const htmlPath = typeof options.html === 'string' ? options.html : 'team-report.html';
    const html = generateHTML(target, findings, agentSections, synthesis, agentSections.bullets);
    fs.writeFileSync(htmlPath, html, 'utf-8');
    output.success(`Team report saved to ${htmlPath}`);
    return;
  }

  // Terminal output
  printBanner();
  console.log(chalk.cyan.bold('  Team Security Report'));
  console.log(chalk.gray(`  Target: ${target}`));
  console.log();

  if (synthesis.riskPosture) {
    const rp = synthesis.riskPosture;
    const color = rp.toLowerCase().includes('critical') ? chalk.red.bold
      : rp.toLowerCase().includes('high') ? chalk.yellow.bold
      : rp.toLowerCase().includes('medium') ? chalk.yellow
      : chalk.green;
    console.log(`  ${chalk.white.bold('Risk Posture:')} ${color(rp)}`);
    console.log();
  }

  const sevColor = { critical: chalk.red.bold, high: chalk.yellow, medium: chalk.blue, low: chalk.gray, info: chalk.gray };
  for (const f of allFindings) {
    const col = sevColor[f.severity] || chalk.white;
    console.log(`  ${col(`[${f.severity.toUpperCase()}]`.padEnd(11))} ${chalk.white(f.title)}`);
    if (f.location) console.log(`  ${' '.repeat(11)} ${chalk.gray(f.location)}`);
    if (f.remediation) console.log(`  ${' '.repeat(11)} ${chalk.green('Fix:')} ${f.remediation.slice(0, 90)}`);
  }

  if (allFindings.length === 0) {
    console.log(chalk.green('  No findings — clean!'));
  }

  console.log();
  if (synthesis.roadmap.immediate) {
    console.log(chalk.red.bold('  ⚡ Immediate (24–48h):'));
    console.log(chalk.gray(`     ${synthesis.roadmap.immediate}`));
  }
  if (synthesis.roadmap.shortTerm) {
    console.log(chalk.yellow.bold('  📅 Short-term (1–2 weeks):'));
    console.log(chalk.gray(`     ${synthesis.roadmap.shortTerm}`));
  }
  if (synthesis.roadmap.longTerm) {
    console.log(chalk.white.bold('  🏗  Long-term (1–3 months):'));
    console.log(chalk.gray(`     ${synthesis.roadmap.longTerm}`));
  }

  console.log();
  console.log(chalk.gray('  Generate HTML report: ') + chalk.cyan(`praxis team-report ${inputFile || '<file>'} --html report.html`));
  console.log();
}
