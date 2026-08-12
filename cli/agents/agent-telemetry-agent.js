/**
 * Agent Telemetry Agent — AI Agent Session Audit Scanner
 * =======================================================
 *
 * Audits workspace and developer environment AI agent session histories
 * (Claude Code, Cursor IDE, Codex CLI, Warp Terminal, Cline) for security hazards:
 *   1. Plaintext secrets / API keys embedded in chat transcripts
 *   2. Unverified or dangerous shell execution logs (curl | bash, rm -rf, reverse shells)
 *   3. Prompt injection payloads in agent interaction trails
 *
 * Maps to: OWASP Agentic AI ASI01 (Prompt Injection), ASI02 (Tool Misuse), ASI05 (Credential Exposure)
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// PATTERNS & REGEXES
// =============================================================================

const SECRET_PATTERNS = [
  {
    rule: 'AGENT_LOG_EXPOSED_OPENAI_KEY',
    title: 'Exposed OpenAI API Key in Agent Session History',
    regex: /sk-(?:proj-)?[a-zA-Z0-9_-]{32,90}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'Plaintext OpenAI API key detected inside AI agent conversation history or execution log.',
    fix: 'Remove secret from session logs and rotate the compromised credential immediately.',
  },
  {
    rule: 'AGENT_LOG_EXPOSED_ANTHROPIC_KEY',
    title: 'Exposed Anthropic API Key in Agent Session History',
    regex: /sk-ant-api03-[a-zA-Z0-9_-]{40,90}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'Plaintext Anthropic API key detected inside AI agent conversation history.',
    fix: 'Revoke the Anthropic key and ensure agent logs are scrubbed before storage.',
  },
  {
    rule: 'AGENT_LOG_EXPOSED_GITHUB_TOKEN',
    title: 'Exposed GitHub Access Token in Agent Log',
    regex: /gh[po]_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'GitHub Personal Access Token or OAuth token detected in agent session state.',
    fix: 'Revoke the token in GitHub settings and purge telemetry logs.',
  },
  {
    rule: 'AGENT_LOG_EXPOSED_AWS_KEY',
    title: 'Exposed AWS Access Key in Agent Log',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'AWS Access Key ID detected in agent transcript.',
    fix: 'Invalidate AWS credentials and configure secret masking in agent tools.',
  },
];

const HAZARDOUS_CMD_PATTERNS = [
  {
    rule: 'AGENT_LOG_PIPE_REMOTE_SHELL',
    title: 'Piped Remote Shell Execution in Agent History',
    regex: /(?:curl|wget)\s+-[^\n|]*\|\s*(?:bash|sh|powershell)/gi,
    severity: 'high',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Agent session recorded execution of remote shell script pipe (curl | bash).',
    fix: 'Audit agent command execution policies to disallow arbitrary unverified pipe scripts.',
  },
  {
    rule: 'AGENT_LOG_RECURSIVE_DESTRUCTION',
    title: 'Destructive File Deletion in Agent Log',
    regex: /rm\s+-rf\s+[/~]/gi,
    severity: 'high',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Agent session recorded execution of recursive destructive command (rm -rf / or ~).',
    fix: 'Enforce workspace path boundaries on agent tool executions.',
  },
];

const PROMPT_INJECTION_PATTERNS = [
  {
    rule: 'AGENT_LOG_PROMPT_OVERRIDE',
    title: 'Prompt Injection Override Payload in Transcript',
    regex: /ignore\s+(?:all\s+)?previous\s+instructions/gi,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'Agent conversation history contains explicit prompt injection override directive.',
    fix: 'Sanitize incoming tool outputs and user inputs before injecting into context window.',
  },
];

// =============================================================================
// AGENT CLASS
// =============================================================================

export class AgentTelemetryAgent extends BaseAgent {
  constructor() {
    super(
      'AgentTelemetryAgent',
      'Audits AI agent session histories and telemetry logs for credentials, hazardous executions, and injection trails',
      'agentic-security'
    );
  }

  /**
   * Run telemetry analysis over codebase and agent session artifacts.
   */
  async analyze(context) {
    const findings = [];
    const { files = [] } = context;

    for (const filePath of files) {
      const lower = filePath.toLowerCase();
      // Target agent session files, json, jsonl, log, vscdb, and markdown transcripts
      const isAgentArtifact =
        lower.includes('.claude/') ||
        lower.includes('.cursor/') ||
        lower.includes('.codex/') ||
        lower.includes('.cline/') ||
        lower.includes('.warp/') ||
        lower.endsWith('.jsonl') ||
        lower.endsWith('.vscdb') ||
        lower.includes('agent') ||
        lower.includes('session');

      if (!isAgentArtifact && !lower.endsWith('.json') && !lower.endsWith('.log')) {
        continue;
      }

      let content = '';
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch (err) {
        continue;
      }

      if (!content || content.length === 0) continue;

      const lines = content.split(/\r?\n/);

      // Audit Secrets
      for (const pattern of SECRET_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
          pattern.regex.lastIndex = 0;
          const match = pattern.regex.exec(lines[i]);
          if (match) {
            findings.push(
              createFinding({
                file: filePath,
                line: i + 1,
                column: match.index + 1,
                severity: pattern.severity,
                category: this.category,
                rule: pattern.rule,
                title: pattern.title,
                description: pattern.description,
                matched: match[0].substring(0, 15) + '...',
                cwe: pattern.cwe,
                owasp: pattern.owasp,
                fix: pattern.fix,
              })
            );
          }
        }
      }

      // Audit Hazardous Commands
      for (const pattern of HAZARDOUS_CMD_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
          pattern.regex.lastIndex = 0;
          const match = pattern.regex.exec(lines[i]);
          if (match) {
            findings.push(
              createFinding({
                file: filePath,
                line: i + 1,
                column: match.index + 1,
                severity: pattern.severity,
                category: this.category,
                rule: pattern.rule,
                title: pattern.title,
                description: pattern.description,
                matched: match[0],
                cwe: pattern.cwe,
                owasp: pattern.owasp,
                fix: pattern.fix,
              })
            );
          }
        }
      }

      // Audit Prompt Injection Indicators
      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
          pattern.regex.lastIndex = 0;
          const match = pattern.regex.exec(lines[i]);
          if (match) {
            findings.push(
              createFinding({
                file: filePath,
                line: i + 1,
                column: match.index + 1,
                severity: pattern.severity,
                category: this.category,
                rule: pattern.rule,
                title: pattern.title,
                description: pattern.description,
                matched: match[0],
                cwe: pattern.cwe,
                owasp: pattern.owasp,
                fix: pattern.fix,
              })
            );
          }
        }
      }
    }

    return findings;
  }
}
