/**
 * Governance Absence-Audits (post-processor)
 * ==========================================
 *
 * Detects MISSING controls rather than present bugs — evidence no generic
 * regex scanner produces:
 *
 *   no-human-oversight — high-blast-radius agent tool authority (financial /
 *                        destructive actions, excessive agency) with no
 *                        approval-gate pattern anywhere in the repo.
 *                        → EU AI Act Art. 14 / ISO 42001 A.12.4 evidence.
 *
 *   no-observability   — a repo that uses AI (LLM findings exist) but wires
 *                        no AI tracing/observability stack at all.
 *                        → EU AI Act Art. 12 / ISO 42001 A.6.2.6 evidence.
 *
 * Runs after the agent pool; findings are merged into the scan results.
 */

import fs from 'fs';
import path from 'path';

// Approval-gate patterns — presence of any of these near high-risk agent
// actions counts as a human-oversight control.
const OVERSIGHT_PATTERNS = [
  /interrupt_before/i, /interrupt_after/i, /human[_-]?in[_-]?the[_-]?loop/i,
  /requires_approval/i, /confirmation_required/i, /requires_confirmation/i,
  /approval[_-]?gate/i, /human[_-]?approval/i, /ask[_-]?for[_-]?confirmation/i,
  /confirm[_-]?before/i, /await[_-]?confirmation/i, /approval[_-]?required/i,
  /manual[_-]?review/i, /two[_-]?person[_-]?rule/i, /maker[_-]?checker/i,
  /human[_-]?check/i, /approve[_-]?tool/i, /permission[_-]?request/i,
  /consent[_-]?check/i, /guardrail/i,
];

// Financial / destructive / high-blast-radius agent action signals.
const HIGH_RISK_ACTION = /financial|refund|payment|charge|transfer|withdraw|payout|invoice|delete|drop|truncate|purge|destroy|write_db|update_record|insert|modify|send_email|send_slack|send_sms|post_to|excessive.?agency|blast.?radius/i;

// AI observability/tracing wiring indicators.
const OBSERVABILITY_INDICATORS = [
  /langsmith/i, /langfuse/i, /helicone/i, /traceloop/i, /openllmetry/i,
  /openinference/i, /opentelemetry/i, /otel/i, /wandb\b/i, /weave\b/i,
  /mlflow/i, /logfire/i, /arize/i, /phoenix\.arize/i, /braintrust/i,
  /langtrace/i, /agentops/i, /lunary/i, /promptfoo/i, /deepeval/i,
];

// Files excluded from the observability check: dependency manifests and
// lockfiles are not proof of wiring (a transitive dep isn't your tracing).
const OBSERVABILITY_EXCLUDE = /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|requirements[^/]*\.txt|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock|node_modules[\\/])/i;

// Manifest-style files where tracing-adjacent names commonly appear as
// dependencies even when nothing is wired.
const MANIFEST_FILES = /(?:package\.json|requirements[^/]*\.txt|pyproject\.toml|Cargo\.toml|go\.mod|Gemfile)$/i;

function readFileSafe(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return '';
  }
}

/**
 * @param {object} args
 * @param {string} args.rootPath   — project root
 * @param {string[]} args.files    — files discovered by the orchestrator
 * @param {object[]} args.findings — agent-pool findings for this run
 * @returns {object[]} governance findings to merge
 */
export function runGovernanceAudits({ rootPath, files = [], findings = [] }) {
  const audits = [];

  // ── no-human-oversight ─────────────────────────────────────────────────
  const riskyActions = findings.filter(f =>
    HIGH_RISK_ACTION.test(`${f.rule || ''} ${f.title || ''}`)
    && (f.category === 'llm' || f.category === 'agentic' || f.category === 'mcp' || f.rule?.startsWith('MCP_'))
  );

  if (riskyActions.length > 0) {
    const repoHasOversight = files.some(f => OVERSIGHT_PATTERNS.some(re => re.test(readFileSafe(f))));
    if (!repoHasOversight) {
      const example = riskyActions[0];
      audits.push({
        file: example.file || path.join(rootPath, 'agent-config'),
        line: 1,
        column: 0,
        severity: 'high',
        category: 'llm',
        rule: 'NO_HUMAN_OVERSIGHT',
        title: 'High-Risk Agent Actions Without Human Oversight Gate',
        description: `${riskyActions.length} finding(s) grant the agent high-blast-radius actions (financial, destructive, or broad tool authority), but no approval-gate pattern (interrupt_before, requires_approval, human_in_the_loop, ...) was found anywhere in the repository. EU AI Act Art. 14 requires effective human oversight for high-risk AI systems.`,
        matched: `oversight patterns absent for ${riskyActions.length} risky action(s)`,
        confidence: 'medium',
        cwe: 'CWE-862',
        owasp: 'ASI08',
        eaa: 'EAA-002',
        fix: 'Add human-approval gates before every financial/destructive agent action (framework interrupts, requires_approval flags, or a two-person rule).',
      });
    }
  }

  // ── no-observability ───────────────────────────────────────────────────
  const usesAi = findings.some(f =>
    f.category === 'llm' || f.category === 'agentic'
    || /(?:llm|openai|anthropic|gemini|prompt|mcp|model|rag)/i.test(`${f.rule || ''} ${f.title || ''}`)
  );

  if (usesAi) {
    const evidenceFiles = files.filter(f => {
      const rel = path.relative(rootPath, f).replace(/\\/g, '/');
      if (OBSERVABILITY_EXCLUDE.test(rel)) return false;
      if (MANIFEST_FILES.test(path.basename(f))) return false;
      return true;
    });
    const wired = evidenceFiles.some(f =>
      OBSERVABILITY_INDICATORS.some(re => re.test(readFileSafe(f)))
    );

    if (!wired) {
      audits.push({
        file: path.join(rootPath, 'observability'),
        line: 1,
        column: 0,
        severity: 'medium',
        category: 'llm',
        rule: 'NO_OBSERVABILITY',
        title: 'AI in Use Without Observability/Tracing',
        description: 'This project calls LLMs, but no AI tracing/observability wiring (LangSmith, Langfuse, Helicone, OpenTelemetry, ...) was found outside dependency manifests. Without traces you cannot detect prompt-injection events, monitor output quality, or respond to AI incidents — EU AI Act Art. 12 / ISO 42001 A.6.2.6.',
        matched: `no tracing wiring in ${evidenceFiles.length} evidence file(s)`,
        confidence: 'medium',
        cwe: 'CWE-778',
        owasp: 'ASI03',
        fix: 'Wire an AI tracing/observability stack (e.g., Langfuse, Helicone, or OpenTelemetry) and log prompts, tool calls, and outputs with retention.',
      });
    }
  }

  return audits;
}
