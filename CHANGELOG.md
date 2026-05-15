# Changelog

All notable changes are documented here.

## Unreleased

- **AI security standards alignment** — modular registry under
  `cli/utils/standards/sources/` covering OWASP LLM Top 10 (2025), MITRE ATLAS,
  NIST AI 600-1 (Generative AI Profile), AVID, OWASP ML Top 10, EU AI Act,
  ISO/IEC 42001, and Google SAIF. Every finding is auto-tagged; reports include
  a `standardsSummary`. New subcommand `praxis scan standard <name> [path]`
  filters findings by standard or control.
- **Two new agents**: `ModelFileScanner` (pickle deserialization risk, missing
  model card) and `PromptInjectionProber` (probe corpus loaded from JSON,
  detects DAN/persona/indirect injection signatures). Total agents: 25.
- **Output schema** — bumped JSON `schemaVersion` to `3`; SARIF results carry
  `properties.standards` and a flat `tags` array for GitHub Code Scanning.
- **Docs** — long-form references moved to `docs/` (`USAGE.md`, `THREAT_INTEL.md`).

## 1.0.0

- Initial release.
- Six-group CLI surface: `scan`, `fix`, `agents`, `intel`, `report`, `project`.
- Top-level shortcuts: `vibe`, `score`, default REPL on no args.
- 23 parallel security agents with per-agent timeout and concurrency control.
- Multi-source threat-intel orchestrator: OSV, GHSA, KEV, EPSS, NVD, Gitleaks
  (free) plus optional Snyk, Socket, GitGuardian, Sonatype, Phylum (paid).
- Per-source TTL caching with stale-cache fallback on transient outages.
- KEV / EPSS finding enrichment in the supply-chain agent.
- Strict-intel CI gate (`--strict-intel --max-intel-age <duration>`).
- LLM-powered agentic fix loop: scan → plan → diff → ask → apply → verify.
- Multi-provider LLM support: Anthropic, OpenAI, DeepSeek, Groq, Together,
  Mistral, xAI, Kimi, Ollama, LM Studio, OpenAI-compatible endpoints.
- Output formatter registry with versioned JSON (schemaVersion 2) and SARIF.
- Shared `cli/core/` modules: `fs`, `errors`, `branding`, `output/`.
- Test suite (`node --test`) covering threat intel, agents, and core utilities.
