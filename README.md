# Praxis

<p align="center">
  <img src="assets/praxis-logo.svg" alt="Praxis Logo" width="620">
</p>

<p align="center">
  <a href="https://github.com/Ganron007/Praxis/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Ganron007/Praxis/ci.yml?label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Node.js-%E2%89%A518.0.0-blue.svg" alt="Node.js: >=18.0.0">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue.svg" alt="Version: 1.0.0">
  <img src="https://img.shields.io/badge/Status-Public%20Beta-yellow.svg" alt="Status: Public Beta">
</p>

**Praxis is an AI-security-first audit CLI with a working fix loop.** 28 parallel
agents scan your codebase — secrets, code vulnerabilities, and the entire AI/agent
attack surface (LLM calls, MCP servers, RAG pipelines, model files, agent configs,
agent telemetry) — then an LLM drafts fixes you approve, applies, verifies, and can
undo. Offline by default. No registration, no data leaves your machine.

Part of the [CADRE](https://github.com/Ganron007/CADRE) platform — fully standalone.

> [!IMPORTANT]
> **Local & gated by design.** Core scans run entirely offline. LLM remediation is
> opt-in, drafts diffs for your approval, writes atomically, and logs every change
> for undo.

---

## What it does

| Capability | In one line |
| --- | --- |
| **AI/agent surface audit** | 28 concurrent agents: prompt injection, MCP tool abuse, agent-memory poisoning, pickle-based model files, RAG, agent session telemetry, local agent-abuse (EAA), and AI infrastructure inventory (gateways, runtimes, API endpoints) |
| **Find → fix → verify** | LLM drafts a diff → you approve → atomic apply → tiered verification ladder (build → tests → re-scan) with auto-revert of failed fixes → undo log |
| **Governance audits** | Detects *missing* controls: no human-oversight gates, no observability wiring — EU AI Act Art. 14 / 12 evidence |
| **MCP trust registry** | Known MCP servers with trust scores (SHA-256 integrity-checked); unverified sources and typosquats flagged |
| **Threat intel** | 6 free feeds cached locally (OSV, GHSA, KEV, EPSS, NVD, Gitleaks) + 5 optional paid; findings enriched with exploit likelihood |
| **Compliance mapping** | Findings tagged against 8 frameworks — OWASP LLM/ML/Agentic, MITRE ATLAS (+ mitigations & case studies), NIST AI 600-1, AVID, EU AI Act, ISO 42001, Google SAIF |
| **Professional report** | Navigable HTML: executive summary, per-finding *what/evidence/fix*, remediation roadmap, 3-state compliance map, score trend |
| **CI-native** | `scan ci` gates, SARIF for Code Scanning, net-new PR gating (fails only on *introduced* findings), `--always-fail-on` floor |

## Quick start

```bash
npm install && npm link

praxis scan .        # full 28-agent audit
praxis fix .         # interactive LLM-guided fixes
praxis agents audit .# audit the AI/agent surface
praxis intel update  # refresh local threat feeds
praxis vibe .        # emoji-graded A–F score
```

`praxis --help` lists everything. Run `praxis` with no args for the interactive REPL.

## How it works

```mermaid
flowchart LR
    A["praxis scan ."] --> B["ReconAgent<br/>(tech-stack profiling)"]
    B --> C["28 agents in parallel"]
    C --> D["Dedupe → verify → score (A–F)"]
    D --> E["Standards mapping<br/>(8 frameworks)"]
    E --> F["Report<br/>(HTML · SARIF · JSON)"]
    F -. "praxis fix" .-> G["LLM drafts diff"]
    G --> H["You approve"]
    H --> I["Atomic apply → verify → undo log"]
```

## Command groups

```
praxis scan       secrets · full · changed · env · redteam · standard · ci
praxis fix        interactive · quick · from-report · rotate · undo · env-template
praxis agents     audit · skill · mcp · bom · serve (MCP server)
praxis intel      update · deps · advisories
praxis report     team · legal · checklist · sbom · benchmark
praxis project    init · doctor · hooks · guard · watch · baseline · plugins · policy
```

## 28 agents at a glance

| Cluster | Agents | Covers |
| --- | --- | --- |
| AI / LLM security | 13 | Prompt injection, MCP, agentic AI, RAG, memory poisoning, model files, agent configs, agent telemetry & abuse (EAA), AI infra inventory |
| Code vulnerabilities | 4 | Injection, SSRF, XSS, ReDoS, exception handling, vibe-coding anti-patterns |
| Auth & API | 3 | JWT flaws, CSRF, IDOR/BOLA, Supabase RLS, unauthenticated routes |
| Supply chain | 3 | Typosquatting, malicious scripts, agent attestation, CI permissions |
| Config & platform | 5 | Docker, K8s, Terraform, CORS/CSP, mobile, CICD, git history, PII |

Full agent list and rule IDs: **[docs/USAGE.md](docs/USAGE.md)**.

## LLM configuration

Optional, for `--deep` analysis and `fix interactive`. Put a `.env` in your working
directory — any OpenAI-compatible gateway works:

```bash
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://your-gateway.example/v1/chat/completions
PRAXIS_LLM_MODEL=your-model
PRAXIS_LLM_REASONING=high   # low | medium | high
```

Template: [`.env.example`](.env.example) · Verify with `praxis project doctor`.

## CI

```yaml
- uses: Ganron007/Praxis@master
  with:
    threshold: '80'
    net-new: 'true'        # fail only on findings introduced by the PR
    fail-on-new: 'high'
    always-fail-on: 'critical'
    sarif: 'true'          # upload to GitHub Code Scanning
```

## Documentation

| Document | Content |
| --- | --- |
| [docs/USAGE.md](docs/USAGE.md) | Complete command & flag reference |
| [docs/THREAT_INTEL.md](docs/THREAT_INTEL.md) | Feed architecture & schemas |
| [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md) | Vendored data attribution |
| [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) | Contributing & agent authoring |
| [.github/SECURITY.md](.github/SECURITY.md) | Reporting vulnerabilities |

## Scope & limitations

Praxis is an **AI-security-first** scanner — it complements, not replaces,
Semgrep/CodeQL-class SAST. Detection is regex + LLM-assisted (no AST/dataflow); a
clean scan is not proof of absence. Standards mapping reports controls with evidence,
not compliance certification. Review fixes before applying them to production.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Praxis contributors.
