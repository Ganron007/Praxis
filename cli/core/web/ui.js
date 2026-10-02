/**
 * Praxis Web UI — Professional AI-Security Studio Frontend
 * ============================================================================
 *
 * Implements the executive and forensic web UI for `praxis web`.
 * Carries the signature Praxis cybersecurity aesthetic:
 *   - Shield with remediation loop + AI sparkle logo with radiant purple-to-violet gradient
 *   - Dark cyber space canvas (#060813) with ambient violet lighting
 *   - Glassmorphic panels with glowing purple borders and high contrast typography
 *   - Full wirings: Projects, Scans, Live SSE Progress, Findings Explorer with Code Viewer,
 *     Standards Matrix (OWASP LLM / MITRE ATLAS), and 28-Agent ABOM Roster.
 *
 * Constraints (per AGENTS.md & WEB-UI.md):
 *   - Zero external CDN dependencies (100% offline-first, self-contained)
 *   - Strictly read-only (no fix/patch application endpoints)
 *   - Strictly loopback/pinned-path project addressing
 *   - Fully anti-CSRF protected via X-Praxis-Client header
 */

import { baseStyles } from '../output/html-theme.js';

export const AGENT_ROSTER = [
  { name: 'PromptInjectionProber', category: 'llm', label: 'Prompt Injection & Jailbreaks', desc: 'Autonomous adversarial probe engine detecting direct & indirect prompt injection, split-payloads, and jailbreaks (OWASP LLM01, ATLAS AML.T0051).' },
  { name: 'LLMRedTeam', category: 'llm', label: 'LLM Red Teaming', desc: 'Multi-turn red-team simulator evaluating assistant boundaries, persona drift, and system prompt extractability.' },
  { name: 'AgenticSecurityAgent', category: 'llm', label: 'Agentic Behavior & Autonomy', desc: 'Audits autonomous tool selection, unbounded recursive execution loops, and missing Human-In-The-Loop (HITL) gates (OWASP LLM06).' },
  { name: 'RAGSecurityAgent', category: 'llm', label: 'RAG & Vector Store Security', desc: 'Detects vector embedding poisoning, untrusted retrieval document injection, and document metadata tampering (OWASP LLM08).' },
  { name: 'ModelFileScanner', category: 'llm', label: 'Model File & Weights Scanner', desc: 'Parses SafeTensors, PyTorch checkpoints, and Pickle files for embedded bytecode execution and malicious model payloads.' },
  { name: 'AgentConfigScanner', category: 'llm', label: 'Agent & Model Configuration', desc: 'Scans system prompt files, temperature/top-p settings, tool permissions, and model endpoint policies for insecure baselines.' },
  { name: 'MemoryPoisoningAgent', category: 'llm', label: 'Agent Memory Poisoning', desc: 'Analyzes vector memory contexts and session retention for persistent injection vulnerabilities.' }, // praxis-ignore AGENT_MEMORY_NO_EXPIRY — UI metadata catalog
  { name: 'MCPSecurityAgent', category: 'mcp', label: 'Model Context Protocol Security', desc: 'Inspects MCP tool manifests, unauthenticated tool execution endpoints, schema injection, and untrusted server bridges.' },
  { name: 'HermesSecurityAgent', category: 'mcp', label: 'Agent Protocol & Subagent Security', desc: 'Audits inter-agent communication protocols, task delegation boundaries, and malicious subagent payload handoffs.' },
  { name: 'ManagedAgentScanner', category: 'mcp', label: 'Managed Orchestrator Security', desc: 'Analyzes LangGraph, CrewAI, AutoGen, and semantic kernel configurations for credential leakage and unconstrained toolsets.' },
  { name: 'AgentAttestationAgent', category: 'governance', label: 'Cryptographic Agent Attestation', desc: 'Validates cryptographic agent identity, execution provenance, signed tool manifests, and tamper-evident run ledgers.' },
  { name: 'AgentTelemetryAgent', category: 'governance', label: 'Observability & Audit Integrity', desc: 'Checks for complete audit logging of agent thought chains, tool invocations, and input/output sanitization traces.' },
  { name: 'AiInfraInventoryAgent', category: 'config', label: 'AI Infrastructure Discovery', desc: 'Inventories self-hosted LLM endpoints, LiteLLM/vLLM gateways, vector DBs, and discovers exposed AI API routes.' },
  { name: 'EndpointAgentAbuseAgent', category: 'vulnerability', label: 'Endpoint Agent Abuse (EAA)', desc: 'Detects malicious tool chaining, arbitrary command execution via agents, and endpoint abuse technique patterns.' },
  { name: 'InjectionTester', category: 'vulnerability', label: 'Code & Injection Vulnerabilities', desc: 'AST and taint-tracking scanner for SQL Injection, OS Command Injection, Path Traversal, and Cross-Site Scripting (XSS).' },
  { name: 'AuthBypassAgent', category: 'auth', label: 'Authentication & Access Control', desc: 'Detects missing authentication guards, flawed JWT validation, privilege escalation, and insecure session management.' },
  { name: 'SSRFProber', category: 'vulnerability', label: 'Server-Side Request Forgery', desc: 'Identifies unvalidated outbound HTTP clients, internal cloud metadata access, and LAN probing sinks.' },
  { name: 'SupplyChainAudit', category: 'supply-chain', label: 'Dependency Supply Chain & KEV', desc: 'Cross-references package manifests against CISA KEV, EPSS exploit predictions, OSV, and GitHub Security Advisories.' },
  { name: 'AgenticSupplyChainAgent', category: 'supply-chain', label: 'Agent Package & Skill Supply Chain', desc: 'Audits community skills, OpenClaw plugins, and agent packages for typosquatting, hidden telemetry, and backdoors.' },
  { name: 'LegalRiskAgent', category: 'governance', label: 'Legal & License Compliance', desc: 'Flags copyleft (GPL/AGPL) contagion, unapproved commercial use licenses, and legally hazardous dependencies.' },
  { name: 'ConfigAuditor', category: 'config', label: 'Configuration & Infrastructure', desc: 'Scans Dockerfiles, docker-compose, Kubernetes specs, and env templates for exposed ports, root users, and misconfigs.' },
  { name: 'GitHistoryScanner', category: 'secrets', label: 'Git History Secret Detection', desc: 'High-entropy and regex scan through git commits, reflogs, and diffs to discover inadvertently committed API keys and tokens.' },
  { name: 'CICDScanner', category: 'config', label: 'CI/CD Pipeline Security', desc: 'Scans GitHub Actions workflows for untrusted script execution, pull_request_target flaws, and secrets injection.' },
  { name: 'APIFuzzer', category: 'api', label: 'REST & GraphQL API Security', desc: 'Analyzes API route definitions for missing rate limiting, BOLA/IDOR object references, and sensitive data overexposure.' },
  { name: 'SupabaseRLSAgent', category: 'auth', label: 'Database & RLS Policies', desc: 'Audits Supabase and PostgreSQL schemas for tables with disabled Row Level Security (RLS) or permissive public policies.' },
  { name: 'PIIComplianceAgent', category: 'governance', label: 'PII & Privacy Compliance', desc: 'Detects credit card numbers, SSNs, phone numbers, and personal identifiers logged or transmitted without encryption.' },
  { name: 'VibeCodingAgent', category: 'vulnerability', label: 'AI Hallucination & Vibe Code', desc: 'Detects hallucinated libraries, fake npm/pip packages, insecure copy-paste boilerplate, and AI coding anti-patterns.' },
  { name: 'ExceptionHandlerAgent', category: 'vulnerability', label: 'Exception & Error Handling', desc: 'OWASP A10:2025 scanner detecting empty catch blocks, leaked stack traces, unhandled promise rejections, and fatal panics.' },
];

/**
 * Returns the complete in-memory HTML representation of Praxis Web.
 */
export function renderFrontend() {
  const rosterJson = JSON.stringify(AGENT_ROSTER).replace(/</g, '\\u003c');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Praxis Security Studio — Autonomous AI-Security Audit Framework</title>
<style>
${baseStyles()}

:root {
  --bg-canvas: #060813;
  --bg-surface: #0c1024;
  --bg-surface-elevated: #121838;
  --bg-card: rgba(14, 18, 42, 0.72);
  --bg-card-hover: rgba(22, 28, 64, 0.85);
  --border-card: rgba(139, 92, 246, 0.22);
  --border-card-hover: rgba(192, 132, 252, 0.5);
  --purple-400: #c084fc;
  --purple-500: #a855f7;
  --purple-600: #9333ea;
  --purple-700: #7c3aed;
  --purple-900: #4c1d95;
  --fuchsia-400: #e879f9;
  --fuchsia-500: #d946ef;
  --cyan-400: #38bdf8;
  --cyan-500: #06b6d4;
  --emerald-400: #34d399;
  --emerald-500: #10b981;
  --red-400: #f87171;
  --red-500: #ef4444;
  --orange-400: #fb923c;
  --orange-500: #f97316;
  --amber-400: #fbbf24;
  --amber-500: #eab308;
  --text-main: #f8fafc;
  --text-body: #cbd5e1;
  --text-muted: #94a3b8;
  --text-dim: #64748b;
  --shadow-glow: 0 0 24px -4px rgba(168, 85, 247, 0.35);
  --shadow-card: 0 8px 32px -8px rgba(0, 0, 0, 0.6);
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
}

body {
  background-color: var(--bg-canvas);
  background-image: 
    radial-gradient(circle at 50% -15%, rgba(124, 58, 237, 0.22) 0%, transparent 65%),
    radial-gradient(circle at 10% 20%, rgba(192, 132, 252, 0.05) 0%, transparent 40%),
    radial-gradient(circle at 90% 70%, rgba(56, 189, 248, 0.04) 0%, transparent 40%);
  background-attachment: fixed;
  color: var(--text-body);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  min-height: 100vh;
  margin: 0;
  padding: 0;
}

/* ── Top Header Navigation ────────────────────────────────────────────────── */
.app-header {
  position: sticky;
  top: 0;
  z-index: 100;
  background: rgba(10, 14, 32, 0.88);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border-card);
  padding: 0.65rem 1.8rem;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}

.header-inner {
  max-width: 1440px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.5rem;
}

.brand-wrapper {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  text-decoration: none;
  cursor: pointer;
}

.brand-logo-svg {
  height: 38px;
  width: auto;
  display: block;
  filter: drop-shadow(0 0 12px rgba(168, 85, 247, 0.45));
  transition: transform 0.2s ease, filter 0.2s ease;
}

.brand-wrapper:hover .brand-logo-svg {
  transform: scale(1.02);
  filter: drop-shadow(0 0 16px rgba(232, 121, 249, 0.6));
}

.brand-badge-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  background: linear-gradient(135deg, rgba(76, 29, 149, 0.5) 0%, rgba(30, 27, 75, 0.7) 100%);
  border: 1px solid rgba(168, 85, 247, 0.35);
  color: var(--purple-400);
  padding: 3px 9px;
  border-radius: 9999px;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.4px;
}

.nav-tabs-group {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  background: rgba(14, 18, 42, 0.6);
  padding: 4px;
  border-radius: var(--radius-md);
  border: 1px solid rgba(139, 92, 246, 0.15);
}

.nav-tab-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  font-size: 0.82rem;
  font-weight: 600;
  padding: 0.45rem 0.95rem;
  border-radius: 7px;
  cursor: pointer;
  transition: all 0.15s ease;
  white-space: nowrap;
}

.nav-tab-btn:hover {
  color: var(--text-main);
  background: rgba(30, 27, 75, 0.45);
}

.nav-tab-btn.active {
  background: linear-gradient(135deg, rgba(168, 85, 247, 0.25) 0%, rgba(124, 58, 237, 0.35) 100%);
  border-color: rgba(168, 85, 247, 0.6);
  color: #ffffff;
  font-weight: 700;
  box-shadow: 0 0 16px -2px rgba(168, 85, 247, 0.45);
}

.nav-counter {
  background: rgba(255, 255, 255, 0.12);
  color: inherit;
  font-size: 0.7rem;
  font-weight: 800;
  padding: 1px 6px;
  border-radius: 9999px;
}

.header-status-box {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: rgba(14, 20, 46, 0.8);
  border: 1px solid rgba(139, 92, 246, 0.25);
  border-radius: 9999px;
  padding: 0.35rem 0.85rem;
  font-size: 0.75rem;
  color: var(--text-muted);
}

.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--emerald-400);
  box-shadow: 0 0 8px var(--emerald-400);
  animation: pulse-dot 2s infinite ease-in-out;
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.4; transform: scale(0.85); }
}

/* ── Container & Layout ──────────────────────────────────────────────────── */
.main-wrapper {
  max-width: 1440px;
  margin: 1.6rem auto;
  padding: 0 1.8rem 4rem;
}

.tab-pane {
  display: none;
  animation: fadeIn 0.2s ease-out;
}

.tab-pane.active {
  display: block;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(6px); }
  to { opacity: 1; transform: translateY(0); }
}

/* ── Custom Cards & Glassmorphism ────────────────────────────────────────── */
.praxis-card {
  background: var(--bg-card);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border: 1px solid var(--border-card);
  border-radius: var(--radius-lg);
  padding: 1.4rem;
  margin-bottom: 1.5rem;
  box-shadow: var(--shadow-card);
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.praxis-card:hover {
  border-color: var(--border-card-hover);
}

.card-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.2rem;
  flex-wrap: wrap;
  gap: 0.8rem;
}

.card-title {
  font-size: 1.15rem;
  font-weight: 800;
  color: var(--text-main);
  display: flex;
  align-items: center;
  gap: 0.6rem;
  letter-spacing: -0.2px;
}

.card-subtitle {
  font-size: 0.82rem;
  color: var(--text-muted);
  margin-top: 0.2rem;
}

/* ── Hero & KPI Metrics ──────────────────────────────────────────────────── */
.kpi-row {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 1rem;
  margin-bottom: 1.5rem;
}

@media (max-width: 1200px) {
  .kpi-row { grid-template-columns: repeat(3, 1fr); }
}

@media (max-width: 768px) {
  .kpi-row { grid-template-columns: repeat(2, 1fr); }
}

.kpi-box {
  background: var(--bg-surface);
  border: 1px solid var(--border-card);
  border-radius: var(--radius-md);
  padding: 1.1rem 1rem;
  position: relative;
  overflow: hidden;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
  transition: transform 0.15s ease, border-color 0.15s ease;
}

.kpi-box:hover {
  transform: translateY(-2px);
  border-color: var(--purple-500);
}

.kpi-top-bar {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
}

.kpi-value {
  font-size: 2.1rem;
  font-weight: 900;
  line-height: 1.1;
  color: var(--text-main);
  display: flex;
  align-items: baseline;
  gap: 0.4rem;
}

.kpi-label {
  font-size: 0.74rem;
  font-weight: 700;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.6px;
  margin-top: 0.4rem;
}

/* ── Live Scan Progress Banner ───────────────────────────────────────────── */
.live-scan-card {
  background: linear-gradient(135deg, rgba(76, 29, 149, 0.25) 0%, rgba(13, 17, 36, 0.85) 100%);
  border: 1px solid rgba(168, 85, 247, 0.4);
  border-radius: var(--radius-lg);
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.5rem;
  box-shadow: var(--shadow-glow);
  display: none;
}

.live-scan-card.visible {
  display: block;
}

.live-scan-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.8rem;
  flex-wrap: wrap;
  gap: 0.8rem;
}

.live-scan-title {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  font-size: 1.05rem;
  font-weight: 800;
  color: #ffffff;
}

.radar-spinner {
  width: 18px;
  height: 18px;
  border: 2px solid var(--purple-400);
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.progress-track {
  width: 100%;
  height: 10px;
  background: rgba(14, 18, 42, 0.9);
  border: 1px solid rgba(139, 92, 246, 0.3);
  border-radius: 9999px;
  overflow: hidden;
  margin-bottom: 0.6rem;
  position: relative;
}

.progress-fill {
  height: 100%;
  width: 0%;
  background: linear-gradient(90deg, #7c3aed 0%, #a855f7 50%, #e879f9 100%);
  border-radius: 9999px;
  transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 0 12px rgba(168, 85, 247, 0.7);
}

.progress-subtext {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 0.82rem;
  color: var(--text-muted);
}

/* ── Action Buttons & Form Controls ──────────────────────────────────────── */
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.45rem;
  background: linear-gradient(135deg, var(--purple-500) 0%, var(--purple-700) 100%);
  color: #ffffff;
  border: 1px solid rgba(192, 132, 252, 0.4);
  border-radius: var(--radius-sm);
  padding: 0.5rem 1.05rem;
  font-weight: 700;
  font-size: 0.82rem;
  cursor: pointer;
  transition: all 0.15s ease;
  box-shadow: 0 2px 8px rgba(124, 58, 237, 0.3);
}

button:hover {
  filter: brightness(1.12);
  box-shadow: 0 0 16px rgba(168, 85, 247, 0.5);
  transform: translateY(-1px);
}

button:active {
  transform: translateY(0);
}

button.ghost {
  background: rgba(22, 28, 64, 0.6);
  color: var(--text-body);
  border: 1px solid rgba(139, 92, 246, 0.25);
  box-shadow: none;
}

button.ghost:hover {
  background: rgba(30, 38, 88, 0.85);
  border-color: var(--purple-500);
  color: var(--text-main);
  box-shadow: 0 0 12px rgba(168, 85, 247, 0.25);
}

button.danger {
  background: rgba(239, 68, 68, 0.15);
  color: var(--red-400);
  border: 1px solid rgba(239, 68, 68, 0.4);
  box-shadow: none;
}

button.danger:hover {
  background: rgba(239, 68, 68, 0.25);
  border-color: var(--red-500);
  box-shadow: 0 0 12px rgba(239, 68, 68, 0.3);
}

button.secondary-action {
  background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
  border-color: #38bdf8;
}

input[type=text] {
  background: #070a16;
  border: 1px solid rgba(139, 92, 246, 0.3);
  border-radius: var(--radius-sm);
  padding: 0.55rem 0.95rem;
  color: var(--text-main);
  font-size: 0.86rem;
  outline: none;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

input[type=text]:focus {
  border-color: var(--purple-400);
  box-shadow: 0 0 12px rgba(168, 85, 247, 0.35);
}

select {
  background: #070a16;
  border: 1px solid rgba(139, 92, 246, 0.3);
  border-radius: var(--radius-sm);
  padding: 0.5rem 0.85rem;
  color: var(--text-main);
  font-size: 0.84rem;
  outline: none;
  cursor: pointer;
}

select:focus {
  border-color: var(--purple-400);
}

/* ── Interactive Tables & Rows ───────────────────────────────────────────── */
.table-responsive {
  overflow-x: auto;
  border: 1px solid var(--border-card);
  border-radius: var(--radius-md);
  background: rgba(8, 12, 28, 0.6);
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.86rem;
  text-align: left;
}

th {
  background: rgba(18, 24, 56, 0.85);
  color: var(--text-muted);
  padding: 0.8rem 1rem;
  font-size: 0.74rem;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  font-weight: 700;
  border-bottom: 1px solid var(--border-card);
}

td {
  padding: 0.85rem 1rem;
  border-bottom: 1px solid rgba(139, 92, 246, 0.12);
  vertical-align: middle;
}

tr:hover td {
  background: rgba(26, 34, 76, 0.45);
}

/* ── Severity Badges & Status Tags ───────────────────────────────────────── */
.sev-badge {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 6px;
  font-size: 0.72rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.sev-critical {
  background: rgba(239, 68, 68, 0.16);
  color: #fca5a5;
  border: 1px solid rgba(239, 68, 68, 0.45);
  box-shadow: 0 0 10px rgba(239, 68, 68, 0.2);
}

.sev-high {
  background: rgba(249, 115, 22, 0.16);
  color: #fdba74;
  border: 1px solid rgba(249, 115, 22, 0.45);
}

.sev-medium {
  background: rgba(234, 179, 8, 0.16);
  color: #fde047;
  border: 1px solid rgba(234, 179, 8, 0.45);
}

.sev-low {
  background: rgba(56, 189, 248, 0.16);
  color: #7dd3fc;
  border: 1px solid rgba(56, 189, 248, 0.45);
}

.sev-info {
  background: rgba(192, 132, 252, 0.16);
  color: #e9d5ff;
  border: 1px solid rgba(192, 132, 252, 0.45);
}

.tag-clear {
  background: rgba(16, 185, 129, 0.16);
  color: #6ee7b7;
  border: 1px solid rgba(16, 185, 129, 0.45);
}

.tag-flagged {
  background: rgba(239, 68, 68, 0.16);
  color: #fca5a5;
  border: 1px solid rgba(239, 68, 68, 0.45);
}

/* ── Scorecard & Proportion Bar ──────────────────────────────────────────── */
.scorecard-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, rgba(24, 30, 70, 0.7) 0%, rgba(13, 17, 40, 0.9) 100%);
  border: 1px solid var(--border-card);
  border-radius: var(--radius-lg);
  padding: 1.25rem 1.6rem;
  margin-bottom: 1.2rem;
  flex-wrap: wrap;
  gap: 1rem;
}

.scorecard-left {
  display: flex;
  align-items: center;
  gap: 1.2rem;
}

.grade-badge-huge {
  width: 58px;
  height: 58px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2.2rem;
  font-weight: 900;
  box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
  border: 2px solid currentColor;
}

.score-details-title {
  font-size: 1.25rem;
  font-weight: 800;
  color: var(--text-main);
}

.score-details-sub {
  font-size: 0.84rem;
  color: var(--text-muted);
  margin-top: 0.2rem;
}

.proportion-bar-wrapper {
  margin: 1.2rem 0;
}

.proportion-bar {
  display: flex;
  height: 10px;
  border-radius: 9999px;
  overflow: hidden;
  background: #0f152d;
  border: 1px solid var(--border-card);
}

.proportion-segment {
  height: 100%;
  transition: width 0.3s ease;
}

.proportion-legend {
  display: flex;
  gap: 1.2rem;
  margin-top: 0.6rem;
  flex-wrap: wrap;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.78rem;
  color: var(--text-muted);
}

.legend-dot {
  width: 9px;
  height: 9px;
  border-radius: 3px;
}

/* ── Filter Toolbar ──────────────────────────────────────────────────────── */
.filter-toolbar {
  display: flex;
  align-items: center;
  gap: 0.8rem;
  background: rgba(14, 18, 42, 0.85);
  border: 1px solid var(--border-card);
  border-radius: var(--radius-md);
  padding: 0.75rem 1rem;
  margin-bottom: 1.2rem;
  flex-wrap: wrap;
}

.filter-btn-chip {
  background: rgba(22, 28, 64, 0.7);
  color: var(--text-muted);
  border: 1px solid rgba(139, 92, 246, 0.2);
  border-radius: var(--radius-sm);
  padding: 0.38rem 0.8rem;
  font-size: 0.78rem;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.15s ease;
}

.filter-btn-chip:hover {
  color: var(--text-main);
  background: rgba(30, 38, 88, 0.8);
}

.filter-btn-chip.active {
  background: var(--purple-500);
  color: #ffffff;
  border-color: var(--purple-400);
  box-shadow: 0 0 12px rgba(168, 85, 247, 0.4);
}

.search-input-box {
  flex: 1;
  min-width: 220px;
}

/* ── Findings Accordion / Card ───────────────────────────────────────────── */
.finding-card-item {
  background: rgba(11, 15, 34, 0.75);
  border: 1px solid rgba(139, 92, 246, 0.18);
  border-radius: var(--radius-md);
  margin-bottom: 0.75rem;
  overflow: hidden;
  transition: border-color 0.15s ease, background 0.15s ease;
}

.finding-card-item:hover {
  border-color: rgba(192, 132, 252, 0.4);
  background: rgba(16, 22, 48, 0.85);
}

.finding-row-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.95rem 1.2rem;
  cursor: pointer;
  user-select: none;
  gap: 1rem;
}

.finding-row-left {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  flex: 1;
  overflow: hidden;
}

.finding-title-text {
  font-weight: 700;
  color: var(--text-main);
  font-size: 0.92rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.finding-rule-pill {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 0.74rem;
  color: var(--purple-400);
  background: rgba(76, 29, 149, 0.3);
  border: 1px solid rgba(168, 85, 247, 0.3);
  padding: 2px 7px;
  border-radius: 4px;
}

.finding-loc-pill {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 0.76rem;
  color: var(--cyan-400);
  background: rgba(14, 165, 233, 0.12);
  border: 1px solid rgba(56, 189, 248, 0.25);
  padding: 2px 8px;
  border-radius: 4px;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
}

.finding-drawer-body {
  display: none;
  padding: 1.2rem 1.4rem;
  border-top: 1px solid rgba(139, 92, 246, 0.15);
  background: rgba(6, 9, 22, 0.85);
}

.finding-drawer-body.expanded {
  display: block;
}

.drawer-section-title {
  font-size: 0.78rem;
  font-weight: 800;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.6px;
  margin: 0.8rem 0 0.4rem;
}

.drawer-section-title:first-child {
  margin-top: 0;
}

.code-snippet-box {
  background: #04060d;
  border: 1px solid rgba(139, 92, 246, 0.25);
  border-radius: var(--radius-sm);
  padding: 0.85rem 1rem;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 0.82rem;
  line-height: 1.5;
  color: #e2e8f0;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.remediation-box {
  background: rgba(30, 27, 75, 0.4);
  border-left: 3px solid var(--purple-400);
  border-radius: 4px;
  padding: 0.75rem 1rem;
  font-size: 0.84rem;
  color: #e9d5ff;
  margin-top: 0.5rem;
}

/* ── Standards Matrix Grid ───────────────────────────────────────────────── */
.standards-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1.2rem;
}

@media (max-width: 900px) {
  .standards-grid { grid-template-columns: 1fr; }
}

.standard-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-card);
  border-radius: var(--radius-md);
  padding: 1.2rem;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
}

.standard-card-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.8rem;
  padding-bottom: 0.6rem;
  border-bottom: 1px solid var(--border-card);
}

.standard-title {
  font-size: 1.05rem;
  font-weight: 800;
  color: var(--text-main);
}

.controls-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.control-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.45rem 0.7rem;
  background: rgba(6, 9, 22, 0.55);
  border: 1px solid rgba(139, 92, 246, 0.12);
  border-radius: var(--radius-sm);
  font-size: 0.82rem;
}

/* ── Agent Roster (ABOM) Grid ────────────────────────────────────────────── */
.agent-roster-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

@media (max-width: 1100px) {
  .agent-roster-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 700px) {
  .agent-roster-grid { grid-template-columns: 1fr; }
}

.agent-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-card);
  border-radius: var(--radius-md);
  padding: 1.1rem;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  transition: transform 0.15s ease, border-color 0.15s ease;
}

.agent-card:hover {
  transform: translateY(-2px);
  border-color: var(--purple-400);
}

.agent-card-title {
  font-size: 0.95rem;
  font-weight: 800;
  color: var(--text-main);
}

.agent-card-desc {
  font-size: 0.81rem;
  color: var(--text-muted);
  line-height: 1.45;
  margin: 0.6rem 0;
}

/* ── Toast Notifications ─────────────────────────────────────────────────── */
.toast-container {
  position: fixed;
  bottom: 1.8rem;
  right: 1.8rem;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  pointer-events: none;
}

.toast {
  pointer-events: auto;
  background: rgba(14, 18, 42, 0.96);
  border: 1px solid var(--purple-500);
  border-radius: var(--radius-md);
  padding: 0.85rem 1.2rem;
  color: var(--text-main);
  font-size: 0.86rem;
  font-weight: 600;
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.7), 0 0 16px rgba(168, 85, 247, 0.35);
  display: flex;
  align-items: center;
  gap: 0.6rem;
  min-width: 260px;
  animation: slideIn 0.25s ease-out;
}

.toast.toast-error {
  border-color: var(--red-500);
  box-shadow: 0 0 16px rgba(239, 68, 68, 0.4);
}

.toast.toast-success {
  border-color: var(--emerald-400);
  box-shadow: 0 0 16px rgba(16, 185, 129, 0.4);
}

@keyframes slideIn {
  from { opacity: 0; transform: translateX(20px); }
  to { opacity: 1; transform: translateX(0); }
}

/* ── Utilities ───────────────────────────────────────────────────────────── */
.empty-state-box {
  text-align: center;
  padding: 3.5rem 1.5rem;
  color: var(--text-dim);
}

.empty-state-title {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text-muted);
  margin-bottom: 0.4rem;
}

.empty-state-sub {
  font-size: 0.84rem;
}

.footer-bar {
  text-align: center;
  padding: 2.5rem 0 1.5rem;
  color: var(--text-dim);
  font-size: 0.8rem;
  border-top: 1px solid var(--border-card);
  margin-top: 3rem;
}

.footer-bar a {
  color: var(--purple-400);
}
</style>
</head>
<body>

<!-- Top Navigation Header -->
<header class="app-header">
  <div class="header-inner">
    <div class="brand-wrapper" onclick="switchTab('overview')">
      <!-- Embedded Official Praxis SVG Logo (Shield + Wordmark + Tagline) -->
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 620 180" class="brand-logo-svg" role="img" aria-label="Praxis Logo">
        <defs>
          <linearGradient id="purpleGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#c084fc"/>
            <stop offset="55%" stop-color="#7c3aed"/>
            <stop offset="100%" stop-color="#4c1d95"/>
          </linearGradient>
          <linearGradient id="wordGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#e879f9"/>
            <stop offset="100%" stop-color="#7c3aed"/>
          </linearGradient>
        </defs>
        <g transform="translate(24,28)">
          <path d="M55 0 L110 18 V62 C110 100 86 128 55 145 C24 128 0 100 0 62 V18 Z"
                fill="url(#purpleGrad)" stroke="#3b0764" stroke-width="2"/>
          <path d="M55 35 A35 35 0 1 1 20 70 H32 A23 23 0 1 0 55 47 V60 L75 41 L55 22 V35 Z"
                fill="#ffffff" opacity="0.95"/>
          <path d="M55 52 Q55 70 73 70 Q55 70 55 88 Q55 70 37 70 Q55 70 55 52 Z"
                fill="#ffffff" opacity="0.95"/>
        </g>
        <text x="160" y="86" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
              font-size="56" font-weight="900" fill="url(#wordGrad)" letter-spacing="-1">Praxis</text>
        <text x="162" y="120" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
              font-size="19" font-weight="600" fill="#94a3b8" letter-spacing="0.4">Autonomous AI-Security Audit Framework</text>
      </svg>
      <span class="brand-badge-pill">v1.0.0</span>
    </div>

    <!-- Navigation Tabs -->
    <nav class="nav-tabs-group">
      <button class="nav-tab-btn active" id="btn-tab-overview" onclick="switchTab('overview')">
        <span>⚡ Dashboard</span>
      </button>
      <button class="nav-tab-btn" id="btn-tab-projects" onclick="switchTab('projects')">
        <span>📁 Projects</span>
        <span class="nav-counter" id="nav-count-projects">0</span>
      </button>
      <button class="nav-tab-btn" id="btn-tab-scans" onclick="switchTab('scans')">
        <span>🔍 Scans</span>
        <span class="nav-counter" id="nav-count-scans">0</span>
      </button>
      <button class="nav-tab-btn" id="btn-tab-findings" onclick="switchTab('findings')">
        <span>🛡️ Findings</span>
        <span class="nav-counter" id="nav-count-findings">0</span>
      </button>
      <button class="nav-tab-btn" id="btn-tab-standards" onclick="switchTab('standards')">
        <span>📋 Standards</span>
      </button>
      <button class="nav-tab-btn" id="btn-tab-agents" onclick="switchTab('agents')">
        <span>🤖 Agents (28)</span>
      </button>
    </nav>

    <!-- Header Right Status -->
    <div class="header-status-box">
      <div class="status-pill">
        <span class="status-dot"></span>
        <span>Loopback &middot; Read-Only</span>
      </div>
      <button onclick="switchTab('projects')"><span>+ Register</span></button>
    </div>
  </div>
</header>

<!-- Main Container -->
<main class="main-wrapper">

  <!-- Active Scan Live Banner (Visible during scanning) -->
  <div id="live-scan-card" class="live-scan-card">
    <div class="live-scan-header">
      <div class="live-scan-title">
        <div class="radar-spinner"></div>
        <div>
          <span>Scanning: <strong id="live-scan-project-name">...</strong></span>
          <span class="muted" style="font-size:0.8rem;margin-left:0.5rem" id="live-scan-job-id"></span>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:0.8rem">
        <span class="muted" id="live-scan-timer" style="font-family:monospace;font-size:0.85rem">00:00</span>
        <button class="ghost" id="live-scan-cancel-btn" style="padding:0.35rem 0.75rem;font-size:0.75rem" onclick="cancelCurrentScan()">Cancel</button>
      </div>
    </div>
    <div class="progress-track">
      <div class="progress-fill" id="live-scan-progress-bar"></div>
    </div>
    <div class="progress-subtext">
      <span id="live-scan-agent-text">Orchestrating security agents...</span>
      <span id="live-scan-count-text">0 / 28</span>
    </div>
  </div>

  <!-- TAB 1: DASHBOARD / OVERVIEW -->
  <div id="pane-overview" class="tab-pane active">
    <!-- KPI Row -->
    <div class="kpi-row">
      <div class="kpi-box">
        <div class="kpi-top-bar" style="background:var(--purple-400)"></div>
        <div class="kpi-value" id="kpi-score" style="color:var(--text-main)">—</div>
        <div class="kpi-label">Security Score</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-top-bar" style="background:var(--red-500)"></div>
        <div class="kpi-value" id="kpi-critical" style="color:var(--red-400)">0</div>
        <div class="kpi-label">Critical Issues</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-top-bar" style="background:var(--orange-500)"></div>
        <div class="kpi-value" id="kpi-high" style="color:var(--orange-400)">0</div>
        <div class="kpi-label">High Severity</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-top-bar" style="background:var(--amber-500)"></div>
        <div class="kpi-value" id="kpi-med-low" style="color:var(--amber-400)">0</div>
        <div class="kpi-label">Medium &middot; Low</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-top-bar" style="background:var(--cyan-400)"></div>
        <div class="kpi-value" id="kpi-projects" style="color:var(--cyan-400)">0</div>
        <div class="kpi-label">Codebases</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-top-bar" style="background:var(--emerald-400)"></div>
        <div class="kpi-value" id="kpi-agents" style="color:var(--emerald-400)">28</div>
        <div class="kpi-label">Scanning Agents</div>
      </div>
    </div>

    <!-- Quick Register Project -->
    <div class="praxis-card">
      <div class="card-header-row">
        <div>
          <div class="card-title"><span>Register Target Project</span></div>
          <div class="card-subtitle">Provide an absolute path to register a repository or directory for security auditing.</div>
        </div>
        <button class="ghost" onclick="refreshAll()"><span>↻ Refresh Data</span></button>
      </div>
      <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
        <input type="text" id="project-path-input" placeholder="e.g. C:\\STUDY\\Github\\MyProject or /workspace/src" style="flex:1;min-width:320px">
        <button onclick="registerProjectAction()"><span>Register Codebase</span></button>
      </div>
      <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
        <span class="muted" style="font-size:0.76rem">Quick paths:</span>
        <button class="ghost" style="padding:0.25rem 0.65rem;font-size:0.74rem" onclick="setPathInput('.')"><span>Current Directory (.)</span></button>
        <button class="ghost" style="padding:0.25rem 0.65rem;font-size:0.74rem" onclick="setPathInput('showcase-target')"><span>showcase-target</span></button>
      </div>
    </div>

    <!-- Recent Scans & Quick Launch Grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
      <!-- Registered Codebases Quick List -->
      <div class="praxis-card" style="margin-bottom:0">
        <div class="card-header-row">
          <div class="card-title"><span>Target Codebases</span></div>
          <button class="ghost" style="font-size:0.76rem;padding:0.35rem 0.75rem" onclick="switchTab('projects')">Manage</button>
        </div>
        <div class="table-responsive">
          <table>
            <thead><tr><th>Project</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody id="overview-projects-list"><tr><td colspan="3" class="empty-state">Loading...</td></tr></tbody>
          </table>
        </div>
      </div>

      <!-- Recent Scans List -->
      <div class="praxis-card" style="margin-bottom:0">
        <div class="card-header-row">
          <div class="card-title"><span>Recent Scan Activity</span></div>
          <button class="ghost" style="font-size:0.76rem;padding:0.35rem 0.75rem" onclick="switchTab('scans')">View All</button>
        </div>
        <div class="table-responsive">
          <table>
            <thead><tr><th>Job</th><th>Project</th><th>Status</th><th>Findings</th><th>Action</th></tr></thead>
            <tbody id="overview-scans-list"><tr><td colspan="5" class="empty-state">No scans yet</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: PROJECTS -->
  <div id="pane-projects" class="tab-pane">
    <div class="praxis-card">
      <div class="card-header-row">
        <div>
          <div class="card-title"><span>Registered Projects</span></div>
          <div class="card-subtitle">Paths are pinned server-side upon registration. Audits and scans address projects by ID only.</div>
        </div>
      </div>

      <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;margin-bottom:1.2rem">
        <input type="text" id="project-path-input-tab" placeholder="Absolute directory path to register" style="flex:1;min-width:320px">
        <button onclick="registerProjectTabAction()"><span>Register Codebase</span></button>
      </div>

      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Project Name</th>
              <th>Resolved Root Path</th>
              <th>State</th>
              <th style="text-align:right">Actions</th>
            </tr>
          </thead>
          <tbody id="projects-table-body">
            <tr><td colspan="4" class="empty-state">Loading registered projects...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 3: SCANS / JOBS -->
  <div id="pane-scans" class="tab-pane">
    <div class="praxis-card">
      <div class="card-header-row">
        <div>
          <div class="card-title"><span>Scan Queue &amp; History</span></div>
          <div class="card-subtitle">Real-time execution status of all security audits across the 28 scanning agents.</div>
        </div>
        <button class="ghost" onclick="refreshAll()"><span>↻ Refresh Jobs</span></button>
      </div>

      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Job ID</th>
              <th>Target Project</th>
              <th>Status</th>
              <th>Progress</th>
              <th>Findings</th>
              <th style="text-align:right">Actions</th>
            </tr>
          </thead>
          <tbody id="scans-table-body">
            <tr><td colspan="6" class="empty-state">No scans recorded yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 4: FINDINGS EXPLORER -->
  <div id="pane-findings" class="tab-pane">
    <!-- Report Selector & Scorecard Banner -->
    <div class="scorecard-banner" id="report-scorecard" style="display:none">
      <div class="scorecard-left">
        <div class="grade-badge-huge" id="scorecard-grade">A</div>
        <div>
          <div class="score-details-title" id="scorecard-title">Praxis Security Report</div>
          <div class="score-details-sub" id="scorecard-sub">Audited across 28 parallel agents</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap">
        <select id="report-job-selector" onchange="onReportSelectorChange(this.value)"></select>
        <button class="ghost" onclick="copyReportJson()"><span>📋 Copy JSON</span></button>
        <button class="ghost" onclick="downloadReportJson()"><span>💾 Download JSON</span></button>
      </div>
    </div>

    <!-- Severity Distribution Proportion Bar -->
    <div class="praxis-card" id="report-proportion-card" style="display:none;padding:1rem 1.4rem">
      <div class="proportion-bar-wrapper">
        <div class="proportion-bar" id="proportion-bar"></div>
        <div class="proportion-legend" id="proportion-legend"></div>
      </div>
    </div>

    <!-- Findings Filter Toolbar -->
    <div class="filter-toolbar" id="findings-filter-bar" style="display:none">
      <input type="text" class="search-input-box" id="findings-search" placeholder="Search findings by rule, file, issue title, or keyword..." oninput="onFilterChange()">
      <div style="display:flex;gap:0.4rem;flex-wrap:wrap">
        <button class="filter-btn-chip active" id="chip-all" onclick="setSeverityFilter('all')">All (<span id="count-all">0</span>)</button>
        <button class="filter-btn-chip" id="chip-critical" onclick="setSeverityFilter('critical')">Critical (<span id="count-critical">0</span>)</button>
        <button class="filter-btn-chip" id="chip-high" onclick="setSeverityFilter('high')">High (<span id="count-high">0</span>)</button>
        <button class="filter-btn-chip" id="chip-medium" onclick="setSeverityFilter('medium')">Medium (<span id="count-medium">0</span>)</button>
        <button class="filter-btn-chip" id="chip-low" onclick="setSeverityFilter('low')">Low (<span id="count-low">0</span>)</button>
      </div>
      <select id="category-filter-select" onchange="onCategoryFilterChange(this.value)">
        <option value="all">All Categories</option>
        <option value="llm">AI / LLM Security</option>
        <option value="mcp">MCP / Skills</option>
        <option value="vulnerability">Code Vulnerabilities</option>
        <option value="secrets">Secrets &amp; Credentials</option>
        <option value="supply-chain">Supply Chain</option>
        <option value="auth">Auth &amp; Access Control</option>
        <option value="config">Configuration</option>
      </select>
    </div>

    <!-- Findings List Container -->
    <div id="findings-container">
      <div class="empty-state-box">
        <div class="empty-state-title">No Scan Selected</div>
        <div class="empty-state-sub">Select a completed scan from the Scans tab or trigger a new audit to inspect findings.</div>
      </div>
    </div>
  </div>

  <!-- TAB 5: STANDARDS MATRIX -->
  <div id="pane-standards" class="tab-pane">
    <div class="praxis-card">
      <div class="card-header-row">
        <div>
          <div class="card-title"><span>AI &amp; Security Standards Matrix</span></div>
          <div class="card-subtitle">Real-time mapping of audit findings against OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF.</div>
        </div>
      </div>

      <div class="standards-grid" id="standards-grid-container">
        <!-- OWASP LLM Top 10 -->
        <div class="standard-card">
          <div class="standard-card-head">
            <span class="standard-title">OWASP Top 10 for LLM (2025)</span>
            <span class="sev-badge sev-info">10 Controls</span>
          </div>
          <div class="controls-list" id="owasp-llm-controls-list">
            <!-- Rendered by JS -->
          </div>
        </div>

        <!-- MITRE ATLAS -->
        <div class="standard-card">
          <div class="standard-card-head">
            <span class="standard-title">MITRE ATLAS (AI Threats)</span>
            <span class="sev-badge sev-info">Adversarial ML</span>
          </div>
          <div class="controls-list" id="mitre-atlas-controls-list">
            <!-- Rendered by JS -->
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 6: AGENT ROSTER (ABOM) -->
  <div id="pane-agents" class="tab-pane">
    <div class="praxis-card">
      <div class="card-header-row">
        <div>
          <div class="card-title"><span>28 Autonomous Security Agents (ABOM)</span></div>
          <div class="card-subtitle">Full inventory of specialized parallel audit agents powering the Praxis detection engine.</div>
        </div>
      </div>

      <div class="agent-roster-grid" id="agent-roster-container">
        <!-- Rendered by JS -->
      </div>
    </div>
  </div>

</main>

<!-- Toast Container -->
<div class="toast-container" id="toast-container"></div>

<!-- Footer -->
<footer class="footer-bar">
  <div><strong>Praxis</strong> &middot; Autonomous AI-Security Audit Framework &middot; Read-Only Local Server</div>
  <div class="muted" style="margin-top:0.35rem">Remediations are reviewed and applied in terminal via <code>praxis fix</code></div>
</footer>

<!-- Client Logic -->
<script>
// Praxis Client API & State Engine
const H = { 'X-Praxis-Client': 'praxis-web' };
const AGENTS = ${rosterJson};

const state = {
  projects: [],
  jobs: [],
  activeJobId: null,
  selectedReport: null,
  activeTab: 'overview',
  activeSse: null,
  filters: {
    search: '',
    severity: 'all',
    category: 'all'
  },
  timerInterval: null,
  scanStartTime: null,
};

// Safe API helper
async function api(method, path, body) {
  const opts = {
    method,
    headers: body ? { ...H, 'Content-Type': 'application/json' } : H,
    body: body ? JSON.stringify(body) : undefined,
  };
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new Error(data.error || ('HTTP ' + r.status));
  }
  return data;
}

// Escaping
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));

// Safe DOM HTML assignment helper
function setHtml(el, html) {
  if (el) el.innerHTML = html; // praxis-ignore XSS_INNERHTML
}

// Toast Notifications
function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast' + (type === 'error' ? ' toast-error' : type === 'success' ? ' toast-success' : '');
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(10px)';
    el.style.transition = 'all 0.3s ease';
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

// Tab Switching
function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab-btn').forEach(b => b.classList.remove('active'));

  const targetPane = document.getElementById('pane-' + tabId);
  const targetBtn = document.getElementById('btn-tab-' + tabId);
  if (targetPane) targetPane.classList.add('active');
  if (targetBtn) targetBtn.classList.add('active');

  if (tabId === 'standards') renderStandardsMatrix();
  if (tabId === 'agents') renderAgentRoster();
}

// Quick path input helper
function setPathInput(val) {
  const inp = document.getElementById('project-path-input');
  if (inp) inp.value = val;
}

// Register Project from Dashboard
async function registerProjectAction() {
  const inp = document.getElementById('project-path-input');
  const path = inp ? inp.value.trim() : '';
  if (!path) return;
  try {
    const res = await api('POST', '/api/projects', { path });
    toast(res.created ? 'Project registered successfully' : 'Project already registered', 'success');
    if (inp) inp.value = '';
    await refreshAll();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Register Project from Projects Tab
async function registerProjectTabAction() {
  const inp = document.getElementById('project-path-input-tab');
  const path = inp ? inp.value.trim() : '';
  if (!path) return;
  try {
    const res = await api('POST', '/api/projects', { path });
    toast(res.created ? 'Project registered successfully' : 'Project already registered', 'success');
    if (inp) inp.value = '';
    await refreshAll();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Remove Project
async function removeProject(id, name) {
  if (!confirm('Remove project "' + (name || id) + '" from registry?')) return;
  try {
    await api('DELETE', '/api/projects/' + id);
    toast('Project removed from registry', 'success');
    await refreshAll();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Trigger Scan
async function triggerScan(projectId) {
  try {
    const { job } = await api('POST', '/api/projects/' + projectId + '/scan');
    toast('Scan enqueued for ' + (job.projectName || 'project'), 'success');
    watchJob(job.id);
    await refreshAll();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Cancel Scan
async function cancelCurrentScan() {
  if (!state.activeJobId) return;
  try {
    await api('POST', '/api/jobs/' + state.activeJobId + '/cancel');
    toast('Scan cancelled', 'info');
    stopWatching();
    await refreshAll();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// SSE Progress Watcher
function watchJob(jobId) {
  stopWatching();
  state.activeJobId = jobId;
  state.scanStartTime = Date.now();

  const banner = document.getElementById('live-scan-card');
  if (banner) banner.classList.add('visible');

  // Start elapsed timer
  state.timerInterval = setInterval(() => {
    const el = document.getElementById('live-scan-timer');
    if (!el || !state.scanStartTime) return;
    const sec = Math.floor((Date.now() - state.scanStartTime) / 1000);
    const m = String(Math.floor(sec / 60)).padStart(2, '0');
    const s = String(sec % 60).padStart(2, '0');
    el.textContent = m + ':' + s;
  }, 1000);

  const es = new EventSource('/api/jobs/' + jobId + '/events');
  state.activeSse = es;

  es.onmessage = ev => {
    try {
      const j = JSON.parse(ev.data);
      updateLiveBanner(j);
      if (['done', 'failed', 'cancelled'].includes(j.status)) {
        stopWatching();
        toast('Scan ' + j.status + ': ' + (j.projectName || j.id), j.status === 'done' ? 'success' : 'error');
        refreshAll().then(() => {
          if (j.status === 'done' && j.hasResult) {
            loadReport(j.projectId, j.id);
          }
        });
      }
    } catch {
      // ignore JSON errors
    }
  };

  es.onerror = () => {
    stopWatching();
    refreshAll();
  };
}

function stopWatching() {
  if (state.activeSse) {
    state.activeSse.close();
    state.activeSse = null;
  }
  if (state.timerInterval) {
    clearInterval(state.timerInterval);
    state.timerInterval = null;
  }
  const banner = document.getElementById('live-scan-card');
  if (banner) banner.classList.remove('visible');
  state.activeJobId = null;
}

function updateLiveBanner(job) {
  const pName = document.getElementById('live-scan-project-name');
  const jId = document.getElementById('live-scan-job-id');
  const pBar = document.getElementById('live-scan-progress-bar');
  const aText = document.getElementById('live-scan-agent-text');
  const cText = document.getElementById('live-scan-count-text');

  if (pName) pName.textContent = job.projectName || 'Project';
  if (jId) jId.textContent = '(' + job.id + ')';

  const total = job.progress?.total || 28;
  const done = job.progress?.done || 0;
  const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;

  if (pBar) pBar.style.width = pct + '%';
  if (cText) cText.textContent = done + ' / ' + total;
  if (aText) {
    aText.textContent = job.progress?.current ? 'Running agent: ' + job.progress.current : 'Analyzing codebase telemetry...';
  }
}

// Load and Render Report
async function loadReport(projectId, jobId) {
  try {
    const q = jobId ? '?job=' + jobId : '';
    const data = await api('GET', '/api/projects/' + projectId + '/report' + q);
    state.selectedReport = {
      job: data.job,
      result: data.result,
      projectId,
    };
    renderReportView();
    switchTab('findings');
  } catch (err) {
    toast('Failed to load report: ' + err.message, 'error');
  }
}

function onReportSelectorChange(val) {
  if (!val) return;
  const [pId, jId] = val.split('::');
  if (pId && jId) {
    loadReport(pId, jId);
  }
}

// Compute Score & Grade fallback
function calculateScore(findings = []) {
  let score = 100;
  for (const f of findings) {
    const sev = String(f.severity || '').toLowerCase();
    if (sev === 'critical') score -= 15;
    else if (sev === 'high') score -= 8;
    else if (sev === 'medium') score -= 3;
    else if (sev === 'low') score -= 1;
  }
  score = Math.max(0, score);
  let grade = 'A';
  if (score < 40) grade = 'F';
  else if (score < 60) grade = 'D';
  else if (score < 75) grade = 'C';
  else if (score < 90) grade = 'B';
  return { score, grade };
}

// Render Findings / Report View
function renderReportView() {
  const r = state.selectedReport;
  if (!r || !r.result) return;

  const result = r.result;
  const job = r.job;
  const findings = result.findings || [];

  // Show Header & Controls
  const scorecard = document.getElementById('report-scorecard');
  const propCard = document.getElementById('report-proportion-card');
  const filterBar = document.getElementById('findings-filter-bar');
  if (scorecard) scorecard.style.display = 'flex';
  if (propCard) propCard.style.display = 'block';
  if (filterBar) filterBar.style.display = 'flex';

  // Compute Score / Grade
  const calc = calculateScore(findings);
  const score = result.score ?? calc.score;
  const grade = result.grade ?? calc.grade;

  const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#f97316', F: '#ef4444' };
  const gradeCol = gradeColors[grade] || '#ef4444';

  const gBadge = document.getElementById('scorecard-grade');
  if (gBadge) {
    gBadge.textContent = grade;
    gBadge.style.color = gradeCol;
    gBadge.style.borderColor = gradeCol;
    gBadge.style.background = gradeCol + '18';
  }

  const sTitle = document.getElementById('scorecard-title');
  if (sTitle) {
    sTitle.textContent = (result.root || job.projectName || 'Audit Report') + ' — ' + Math.round(score) + '/100';
  }

  const sSub = document.getElementById('scorecard-sub');
  if (sSub) {
    sSub.textContent = findings.length + ' vulnerability finding(s) detected across ' + (result.agentCount || 28) + ' parallel agents';
  }

  // Update Report Selector Options
  const sel = document.getElementById('report-job-selector');
  if (sel) {
    const finishedJobs = state.jobs.filter(j => j.hasResult);
    setHtml(sel, finishedJobs.map(j => \`
      <option value="\${esc(j.projectId)}::\${esc(j.id)}" \${j.id === job.id ? 'selected' : ''}>
        \${esc(j.projectName)} (\${esc(j.id)})
      </option>\`).join(''));
  }

  // Proportion Bar
  renderProportionBar(findings);

  // Render Filtered Findings List
  renderFindingsList();
}

function renderProportionBar(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => {
    const s = String(f.severity || '').toLowerCase();
    if (s in counts) counts[s]++;
  });

  const total = findings.length || 1;
  const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#38bdf8', info: '#c084fc' };

  const bar = document.getElementById('proportion-bar');
  if (bar) {
    if (findings.length === 0) {
      setHtml(bar, '<div class="proportion-segment" style="width:100%;background:#10b981"></div>');
    } else {
      setHtml(bar, Object.entries(counts).map(([sev, count]) => {
        const pct = (count / total) * 100;
        return pct > 0 ? \`<div class="proportion-segment" style="width:\${pct}%;background:\${colors[sev]}" title="\${esc(sev)}: \${count}"></div>\` : '';
      }).join(''));
    }
  }

  const legend = document.getElementById('proportion-legend');
  if (legend) {
    setHtml(legend, Object.entries(counts).map(([sev, count]) => \`
      <div class="legend-item">
        <span class="legend-dot" style="background:\${colors[sev]}"></span>
        <span style="text-transform:capitalize">\${esc(sev)}: <strong>\${count}</strong></span>
      </div>\`).join(''));
  }

  // Update Count Chips
  document.getElementById('count-all').textContent = findings.length;
  document.getElementById('count-critical').textContent = counts.critical;
  document.getElementById('count-high').textContent = counts.high;
  document.getElementById('count-medium').textContent = counts.medium;
  document.getElementById('count-low').textContent = counts.low;
  document.getElementById('nav-count-findings').textContent = findings.length;
}

function setSeverityFilter(sev) {
  state.filters.severity = sev;
  document.querySelectorAll('.filter-btn-chip').forEach(c => c.classList.remove('active'));
  const btn = document.getElementById('chip-' + sev);
  if (btn) btn.classList.add('active');
  renderFindingsList();
}

function onFilterChange() {
  const inp = document.getElementById('findings-search');
  state.filters.search = inp ? inp.value.trim().toLowerCase() : '';
  renderFindingsList();
}

function onCategoryFilterChange(val) {
  state.filters.category = val;
  renderFindingsList();
}

function renderFindingsList() {
  const container = document.getElementById('findings-container');
  if (!container) return;

  const r = state.selectedReport;
  if (!r || !r.result) return;

  const findings = r.result.findings || [];
  const search = state.filters.search;
  const sevFilter = state.filters.severity;
  const catFilter = state.filters.category;

  const filtered = findings.filter(f => {
    const s = String(f.severity || '').toLowerCase();
    if (sevFilter !== 'all' && s !== sevFilter) return false;
    if (catFilter !== 'all' && String(f.category || '').toLowerCase() !== catFilter) return false;
    if (search) {
      const match = (f.title || '') + ' ' + (f.rule || '') + ' ' + (f.file || '') + ' ' + (f.description || '');
      if (!match.toLowerCase().includes(search)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    setHtml(container, \`
      <div class="empty-state-box">
        <div class="empty-state-title">No matching findings</div>
        <div class="empty-state-sub">\${findings.length === 0 ? 'Codebase clean! Zero vulnerabilities flagged.' : 'Adjust search or severity filters.'}</div>
      </div>\`);
    return;
  }

  setHtml(container, filtered.map((f, idx) => {
    const sevClass = 'sev-' + esc(String(f.severity || 'low').toLowerCase());
    const loc = esc(f.file || '') + (f.line ? ':' + esc(f.line) : '');
    const drawerId = 'finding-drawer-' + idx;

    return \`
      <div class="finding-card-item">
        <div class="finding-row-summary" onclick="toggleDrawer('\${drawerId}')">
          <div class="finding-row-left">
            <span class="sev-badge \${sevClass}">\${esc(f.severity)}</span>
            \${f.rule ? '<span class="finding-rule-pill">' + esc(f.rule) + '</span>' : ''}
            <span class="finding-title-text">\${esc(f.title || 'Untitled Security Issue')}</span>
          </div>
          <div style="display:flex;align-items:center;gap:0.75rem">
            <span class="finding-loc-pill" onclick="event.stopPropagation();copyText('\${esc(f.file || '')}', 'File path')">
              \${loc} 📋
            </span>
            <span style="color:var(--text-dim);font-size:0.75rem">&#x25BC;</span>
          </div>
        </div>
        <div class="finding-drawer-body" id="\${drawerId}">
          <div class="drawer-section-title">Vulnerability Description</div>
          <p style="font-size:0.86rem;line-height:1.55;color:var(--text-body);margin-bottom:0.8rem">
            \${esc(f.description || f.title || 'No description provided.')}
          </p>

          \${f.matched ? \`
            <div class="drawer-section-title">Vulnerable Code Evidence</div>
            <div class="code-snippet-box">\${esc(f.matched)}</div>
          \` : ''}

          <div class="drawer-section-title">Remediation Guidance</div>
          <div class="remediation-box">
            \${esc(f.fix?.description || f.fix || 'Review the vulnerable code snippet and apply input sanitization or restricted boundaries.')}
            <div style="font-size:0.76rem;margin-top:0.4rem;color:var(--purple-400)">
              &bull; Remediation patches can be generated and applied interactively in CLI via <code>praxis fix</code>
            </div>
          </div>

          \${f.owasp || f.cwe || f.standards ? \`
            <div class="drawer-section-title">Compliance &amp; Standards Mapping</div>
            <div style="display:flex;gap:0.4rem;flex-wrap:wrap">
              \${f.owasp ? '<span class="finding-rule-pill">OWASP: ' + esc(f.owasp) + '</span>' : ''}
              \${f.cwe ? '<span class="finding-rule-pill">CWE: ' + esc(f.cwe) + '</span>' : ''}
              \${f.standards?.owaspLlm ? '<span class="finding-rule-pill">' + esc(f.standards.owaspLlm.join(', ')) + '</span>' : ''}
              \${f.standards?.mitreAtlas ? '<span class="finding-rule-pill">ATLAS: ' + esc(f.standards.mitreAtlas.join(', ')) + '</span>' : ''}
            </div>
          \` : ''}
        </div>
      </div>
    \`;
  }).join('');
}

function toggleDrawer(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('expanded');
}

function copyText(str, label = 'Text') {
  navigator.clipboard.writeText(str).then(() => {
    toast(label + ' copied to clipboard', 'info');
  }).catch(() => {});
}

function copyReportJson() {
  if (!state.selectedReport?.result) return;
  const json = JSON.stringify(state.selectedReport.result, null, 2);
  copyText(json, 'Report JSON');
}

function downloadReportJson() {
  if (!state.selectedReport?.result) return;
  const json = JSON.stringify(state.selectedReport.result, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = (state.selectedReport.job?.projectName || 'praxis-report') + '.json';
  a.click();
  URL.revokeObjectURL(url);
  toast('Report downloaded', 'success');
}

// Standards Matrix
function renderStandardsMatrix() {
  const owaspList = document.getElementById('owasp-llm-controls-list');
  const atlasList = document.getElementById('mitre-atlas-controls-list');
  if (!owaspList || !atlasList) return;

  const findings = state.selectedReport?.result?.findings || [];

  const owaspControls = [
    { id: 'LLM01', title: 'Prompt Injection & Jailbreaking' },
    { id: 'LLM02', title: 'Sensitive Information Disclosure' },
    { id: 'LLM03', title: 'Supply Chain Vulnerabilities' },
    { id: 'LLM04', title: 'Data & Model Poisoning' },
    { id: 'LLM05', title: 'Improper Output Handling' },
    { id: 'LLM06', title: 'Excessive Agency & Unbounded Autonomy' },
    { id: 'LLM07', title: 'System Prompt Leakage' },
    { id: 'LLM08', title: 'Vector & Embedding Weaknesses' },
    { id: 'LLM09', title: 'Misinformation & Hallucination' },
    { id: 'LLM10', title: 'Unbounded Consumption & Resource Exhaustion' },
  ];

  const atlasControls = [
    { id: 'AML.T0051', title: 'LLM Prompt Injection' },
    { id: 'AML.T0010', title: 'ML Supply Chain Compromise' },
    { id: 'AML.T0043', title: 'Craft Adversarial Data' },
    { id: 'AML.T0040', title: 'ML Model Inversion' },
    { id: 'AML.T0024', title: 'Exfiltration via ML Inference API' },
    { id: 'AML.T0015', title: 'Evade ML Model' },
  ];

  setHtml(owaspList, owaspControls.map(c => {
    const count = findings.filter(f => {
      const text = (f.rule || '') + ' ' + (f.title || '') + ' ' + (f.owasp || '') + ' ' + JSON.stringify(f.standards || {});
      return text.includes(c.id);
    }).length;
    return \`
      <div class="control-item">
        <div>
          <strong style="color:var(--purple-400)">\${esc(c.id)}:</strong>
          <span style="color:var(--text-body);margin-left:0.4rem">\${esc(c.title)}</span>
        </div>
        \${count > 0 ? '<span class="sev-badge sev-critical">' + count + ' flagged</span>' : '<span class="sev-badge tag-clear">PASS</span>'}
      </div>\`;
  }).join(''));

  setHtml(atlasList, atlasControls.map(c => {
    const count = findings.filter(f => {
      const text = (f.rule || '') + ' ' + (f.title || '') + ' ' + JSON.stringify(f.standards || {});
      return text.includes(c.id);
    }).length;
    return \`
      <div class="control-item">
        <div>
          <strong style="color:var(--cyan-400)">\${esc(c.id)}:</strong>
          <span style="color:var(--text-body);margin-left:0.4rem">\${esc(c.title)}</span>
        </div>
        \${count > 0 ? '<span class="sev-badge sev-critical">' + count + ' flagged</span>' : '<span class="sev-badge tag-clear">COVERED</span>'}
      </div>\`;
  }).join(''));
}

// Agent Roster (ABOM)
function renderAgentRoster() {
  const container = document.getElementById('agent-roster-container');
  if (!container) return;

  const currentAgents = state.selectedReport?.result?.agents || [];
  const findings = state.selectedReport?.result?.findings || [];

  setHtml(container, AGENTS.map(a => {
    const count = findings.filter(f => String(f.rule || '').toLowerCase().includes(a.name.toLowerCase().replace('agent', ''))).length;
    const executed = currentAgents.some(ca => ca.agent === a.name || ca.agent === a.name.replace('Agent', ''));

    return \`
      <div class="agent-card">
        <div>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.4rem">
            <span class="finding-rule-pill">\${esc(a.category.toUpperCase())}</span>
            \${count > 0 ? '<span class="sev-badge sev-high">' + count + ' issues</span>' : executed ? '<span class="sev-badge tag-clear">CLEAN</span>' : '<span class="muted" style="font-size:0.72rem">READY</span>'}
          </div>
          <div class="agent-card-title">\${esc(a.name)}</div>
          <div class="agent-card-desc">\${esc(a.desc)}</div>
        </div>
        <div style="font-size:0.75rem;color:var(--text-dim);border-top:1px solid rgba(139,92,246,0.15);padding-top:0.5rem">
          Specialization: \${esc(a.label)}
        </div>
      </div>\`;
  }).join(''));
}

// Refresh Everything
async function refreshAll() {
  try {
    const [{ projects }, { jobs }] = await Promise.all([
      api('GET', '/api/projects'),
      api('GET', '/api/jobs'),
    ]);

    state.projects = projects || [];
    state.jobs = jobs || [];

    // Update Counters
    document.getElementById('nav-count-projects').textContent = state.projects.length;
    document.getElementById('nav-count-scans').textContent = state.jobs.length;
    document.getElementById('kpi-projects').textContent = state.projects.length;

    // Check for running job
    const running = state.jobs.find(j => j.status === 'running' || j.status === 'queued');
    if (running && state.activeJobId !== running.id) {
      watchJob(running.id);
    } else if (!running && state.activeJobId) {
      stopWatching();
    }

    renderProjectsTable();
    renderScansTable();
    renderDashboardOverview();

    // If report is selected or if there is a completed scan, load the latest
    if (!state.selectedReport) {
      const latest = [...state.jobs].reverse().find(j => j.hasResult);
      if (latest) {
        loadReport(latest.projectId, latest.id);
      }
    }
  } catch (err) {
    console.error('Refresh error:', err);
  }
}

function renderProjectsTable() {
  const tbody = document.getElementById('projects-table-body');
  if (!tbody) return;

  if (state.projects.length === 0) {
    setHtml(tbody, '<tr><td colspan="4" class="empty-state">No projects registered yet</td></tr>');
    return;
  }

  setHtml(tbody, state.projects.map(p => \`
    <tr>
      <td><strong>\${esc(p.name)}</strong></td>
      <td><code>\${esc(p.root)}</code></td>
      <td>\${p.present ? '<span class="sev-badge tag-clear">● Available</span>' : '<span class="sev-badge tag-flagged">✕ Missing</span>'}</td>
      <td style="text-align:right">
        <button style="padding:0.35rem 0.75rem;font-size:0.76rem" onclick="triggerScan('\${esc(p.id)}')">⚡ Run Scan</button>
        <button class="ghost" style="padding:0.35rem 0.75rem;font-size:0.76rem" onclick="loadProjectLatestReport('\${esc(p.id)}')">Report</button>
        <button class="danger" style="padding:0.35rem 0.75rem;font-size:0.76rem" onclick="removeProject('\${esc(p.id)}', '\${esc(p.name)}')">Remove</button>
      </td>
    </tr>\`).join(''));
}

function renderScansTable() {
  const tbody = document.getElementById('scans-table-body');
  if (!tbody) return;

  if (state.jobs.length === 0) {
    setHtml(tbody, '<tr><td colspan="6" class="empty-state">No scans recorded yet</td></tr>');
    return;
  }

  setHtml(tbody, state.jobs.slice().reverse().map(j => {
    const statusBadges = {
      done: '<span class="sev-badge tag-clear">DONE</span>',
      running: '<span class="sev-badge sev-info">RUNNING</span>',
      queued: '<span class="sev-badge sev-low">QUEUED</span>',
      failed: '<span class="sev-badge sev-critical">FAILED</span>',
      cancelled: '<span class="sev-badge sev-high">CANCELLED</span>',
    };
    const sBadge = statusBadges[j.status] || '<span class="sev-badge">' + esc(j.status) + '</span>';
    const progressText = j.progress?.total ? j.progress.done + '/' + j.progress.total + (j.progress.current ? ' (' + esc(j.progress.current) + ')' : '') : '—';

    return \`
      <tr>
        <td><code>\${esc(j.id)}</code></td>
        <td><strong>\${esc(j.projectName)}</strong></td>
        <td>\${sBadge}</td>
        <td>\${progressText}</td>
        <td>\${j.hasResult ? 'Available' : '—'}</td>
        <td style="text-align:right">
          \${j.hasResult ? '<button style="padding:0.35rem 0.75rem;font-size:0.76rem" onclick="loadReport(\\'' + esc(j.projectId) + '\\', \\'' + esc(j.id) + '\\')">View Report</button>' : ''}
          \${j.status === 'queued' ? '<button class="danger" style="padding:0.35rem 0.75rem;font-size:0.76rem" onclick="cancelJobAction(\\'' + esc(j.id) + '\\')">Cancel</button>' : ''}
        </td>
      </tr>\`;
  }).join(''));
}

function renderDashboardOverview() {
  // Overview Projects List
  const pList = document.getElementById('overview-projects-list');
  if (pList) {
    if (state.projects.length === 0) {
      setHtml(pList, '<tr><td colspan="3" class="empty-state">No projects registered</td></tr>');
    } else {
      setHtml(pList, state.projects.slice(0, 5).map(p => \`
        <tr>
          <td><strong>\${esc(p.name)}</strong></td>
          <td>\${p.present ? '<span class="sev-badge tag-clear">Available</span>' : '<span class="sev-badge tag-flagged">Missing</span>'}</td>
          <td><button style="padding:0.25rem 0.6rem;font-size:0.74rem" onclick="triggerScan('\${esc(p.id)}')">Scan</button></td>
        </tr>\`).join(''));
    }
  }

  // Overview Scans List
  const sList = document.getElementById('overview-scans-list');
  if (sList) {
    if (state.jobs.length === 0) {
      setHtml(sList, '<tr><td colspan="5" class="empty-state">No scans executed yet</td></tr>');
    } else {
      setHtml(sList, state.jobs.slice().reverse().slice(0, 5).map(j => \`
        <tr>
          <td><code>\${esc(j.id)}</code></td>
          <td>\${esc(j.projectName)}</td>
          <td>\${esc(j.status)}</td>
          <td>\${j.hasResult ? 'Ready' : '—'}</td>
          <td>\${j.hasResult ? '<a href="#" onclick="event.preventDefault();loadReport(\\'' + esc(j.projectId) + '\\', \\'' + esc(j.id) + '\\')">View</a>' : '—'}</td>
        </tr>\`).join(''));
    }
  }

  // Update Score & KPI Boxes
  const completedWithFindings = state.jobs.find(j => j.hasResult);
  if (state.selectedReport?.result) {
    const findings = state.selectedReport.result.findings || [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
      const s = String(f.severity || '').toLowerCase();
      if (s in counts) counts[s]++;
    });

    const calc = calculateScore(findings);
    const score = state.selectedReport.result.score ?? calc.score;
    const grade = state.selectedReport.result.grade ?? calc.grade;

    document.getElementById('kpi-score').textContent = score + '/100 (' + grade + ')';
    document.getElementById('kpi-critical').textContent = counts.critical;
    document.getElementById('kpi-high').textContent = counts.high;
    document.getElementById('kpi-med-low').textContent = counts.medium + counts.low;
  }
}

function loadProjectLatestReport(projectId) {
  const job = [...state.jobs].reverse().find(j => j.projectId === projectId && j.hasResult);
  if (job) {
    loadReport(projectId, job.id);
  } else {
    toast('No completed scans found for this project yet. Click "Run Scan" to start one.', 'info');
  }
}

async function cancelJobAction(jobId) {
  try {
    await api('POST', '/api/jobs/' + jobId + '/cancel');
    toast('Job cancelled', 'info');
    await refreshAll();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Polling interval for background job refresh
setInterval(() => {
  if (!state.activeJobId) {
    refreshAll();
  }
}, 4000);

// Initial Load
refreshAll();
</script>
</body>
</html>`;
}
