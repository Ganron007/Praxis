# Changelog

All notable changes are documented here.

## 1.0.0 (release)

**28 parallel security agents** covering the AI/agent attack surface:
- AI/LLM: LLMRedTeam, MCPSecurityAgent, AgenticSecurityAgent, RAGSecurityAgent,
  MemoryPoisoningAgent, AgentConfigScanner, ModelFileScanner,
  PromptInjectionProber (23-probe corpus: jailbreak frames, delimiter probes,
  invisible-char/bidi/Zalgo steganography, mixed-script homoglyphs),
  ManagedAgentScanner, HermesSecurityAgent, AgentAttestationAgent,
  AgentTelemetryAgent (session secrets, hazardous commands, exfiltration —
  zero-width/bidi/JWT/PEM/bearer/encoded-URL/base64 — and forensics:
  tool-error exits, permission-mode escalation, sub-agent sidechains,
  parse-error tampering), **EndpointAgentAbuseAgent** (EAA catalog: hook
  persistence, MCP env-expansion, gateway overrides, committed agent state),
  **AiInfraInventoryAgent** (model gateways, AI runtimes in IaC, API endpoints
  with BOLA candidates).
- Classic: InjectionTester, AuthBypassAgent, SSRFProber, SupplyChainAudit,
  ConfigAuditor, MobileScanner, GitHistoryScanner, CICDScanner, APIFuzzer,
  SupabaseRLSAgent, PIIComplianceAgent, VibeCodingAgent,
  ExceptionHandlerAgent, ReconAgent.

**Governance absence-audits** — `NO_HUMAN_OVERSIGHT` (EU AI Act Art. 14) and
`NO_OBSERVABILITY` (Art. 12) post-processors.

**MCP trust registry** — curated known-MCP registry with trust scores and
SHA-256 integrity check; `MCP_UNVERIFIED_SOURCE` rule.

**Standards mapping (8 frameworks)** — OWASP LLM/ML/Agentic, MITRE ATLAS
(official 2026-04 knowledge snapshot: mitigations + case studies per flagged
technique), NIST AI 600-1, AVID, EU AI Act (18 article-level controls),
ISO 42001 (21 Annex controls), Google SAIF. 3-state coverage map:
flagged / no evidence / no detection rule.

**Fix loop with verification ladder** — build → test → re-scan tiers, all
executable oracles; evidence-fed plan retries (`--max-attempts`); automatic
revert of failed fixes; undo log with verification classes.

**CI/CD** — `scan ci` with `--always-fail-on` floor (beats baselines) and
`--include-findings`; GitHub Action with net-new PR gating (base-vs-head
diff by `file:rule` identity).

**Professional HTML report** — sidebar navigation, executive risk narrative,
categorized finding cards (what it means · evidence · how to fix ·
references), remediation roadmap, compliance matrix, AI attack-surface lanes,
score trend, scope & limitations.

**LLM configuration via `.env`** — `OPENAI_API_KEY` / `OPENAI_BASE_URL` /
`PRAXIS_LLM_MODEL` / `PRAXIS_LLM_REASONING`, loaded from cwd; works with any
OpenAI-compatible gateway.

**Threat intel** — 6 free feeds (OSV, GHSA, KEV, EPSS, NVD, Gitleaks) +
5 optional paid; TTL caching; subset updates preserve other sources' data.

**Hardening** — symlink refusal, walker file caps, ReDoS guard on corpus
regexes, central secret redaction in report output, plugin sandboxing,
MCP server (6 tools), SBOM/ABOM (CycloneDX), 26 legacy command aliases,
plugin system (`.praxis/agents/*.js`), hooks/guard/watch/baseline/policy.

**Testing** — 259 tests across 6 suites; CI on Node 18/20/22 with dogfood scan.

## Pre-release

- **AI security standards alignment** - modular registry under
  `cli/utils/standards/sources/` covering OWASP LLM Top 10 (2025), MITRE ATLAS,
  NIST AI 600-1 (Generative AI Profile), AVID, OWASP ML Top 10, EU AI Act,
  ISO/IEC 42001, and Google SAIF. Every finding is auto-tagged; reports include
  a `standardsSummary`. New subcommand `praxis scan standard <name> [path]`
  filters findings by standard or control.
- **Output schema** - bumped JSON `schemaVersion` to `3`; SARIF results carry
  `properties.standards` and a flat `tags` array for GitHub Code Scanning.
- **Docs** - long-form references moved to `docs/` (`USAGE.md`, `THREAT_INTEL.md`).
- Initial release: six-group CLI surface (`scan`, `fix`, `agents`, `intel`,
  `report`, `project`), top-level shortcuts (`vibe`, `score`, default REPL),
  multi-provider LLM support (Anthropic, OpenAI, DeepSeek, Groq, Together,
  Mistral, xAI, Kimi, Ollama, LM Studio, OpenAI-compatible endpoints),
  strict-intel CI gate (`--strict-intel --max-intel-age <duration>`).
