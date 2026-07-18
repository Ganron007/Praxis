# Praxis — Architecture Review & Pre-Release Audit

> **Date:** 2026-07-17
> **Reviewer:** Independent engineering review board
> **Scope:** Read-only assessment — no modifications made
> **Overall Grade:** B (Solid Beta — Not Yet Release-Ready)
> **Release Readiness Score:** 62/100

---

## Executive Summary

Praxis is a genuinely substantive project filling a real gap in AI-security tooling. It's the only scanner treating AI-augmented codebases (LLM calls, MCP, RAG, agent configs, model files, prompt-injection surface) as a first-class target while shipping a working fix loop. The architecture is clean, the agent framework is well-designed, and the threat intel pipeline is real.

However, several critical gaps prevent immediate public release:

- **No CI workflow exists** (despite a badge claiming otherwise)
- **Test coverage is incomplete** (6 test files for 38+ commands and 25 agents)
- **Plugin system runs arbitrary code unsandboxed**
- **Stale inconsistencies** between documentation and implementation

---

## 1. Architecture Walkthrough

### Pipeline Architecture

Praxis follows a clean pipeline with clear separation of concerns:

```
CLI Ingress (commander — 38 subcommands in 6 groups)
    ↓
ReconAgent (tech stack profiling — frameworks, languages, vectors)
    ↓
Orchestrator (25 agents, parallel chunks of 6, 30s timeout each)
    ↓
Post-Processing Pipeline:
    Deduplication (file:line:rule)
    → VerifierAgent (downgrade unconfirmed findings)
    → DeepAnalyzer (optional 3-tier LLM taint analysis)
    → ScoringEngine (weighted category deductions → 0-100 + A-F grade)
    → StandardsMapper (8 AI security frameworks)
    ↓
Output Formatters (JSON / SARIF / HTML / CSV / Markdown)
    ↓
Fix Loop (LLM-powered: scan → plan → diff → ask → apply → verify → undo)
```

### Project Structure

| Directory | Purpose | Assessment |
|---|---|---|
| `cli/bin/praxis.js` | Entry point, 38 subcommands in 6 verb-led groups | ✅ Well-organized |
| `cli/agents/` | 25 scanning agents + orchestrator + scoring engine | ✅ Real implementations, not stubs |
| `cli/commands/` | 38 command implementations | ⚠️ Variable quality, naming confusion |
| `cli/core/` | Shared utilities (`fs.js`, `errors.js`, `branding.js`, `output/`) | ✅ Clean registry pattern |
| `cli/utils/intel/` | 11 threat intel sources + merge + TTL cache | ✅ Real fetchers with graceful degradation |
| `cli/utils/standards/` | 8 AI security standards mappers | ✅ Registry pattern, extensible |
| `cli/providers/` | Multi-LLM provider abstraction | ✅ 5 providers, structured output |
| `cli/data/` | Bundled seed data + probes | ✅ |
| `cli/__tests__/` | 6 test files (~2,837 lines) | ⚠️ Incomplete coverage |
| `docs/` | USAGE.md, THREAT_INTEL.md, IMPROVEMENT-PLAN.md | ⚠️ Sparse |

### Runtime Dependencies (5 total)

| Package | Version | Purpose |
|---|---|---|
| `chalk` | ^5.3.0 | Terminal colors |
| `commander` | ^12.1.0 | CLI parsing |
| `fast-glob` | ^3.3.3 | File discovery |
| `ora` | ^8.0.1 | Terminal spinners |
| `write-file-atomic` | ^7.0.0 | Atomic file writes |

**Assessment:** Minimal dependency surface. All well-maintained, widely-used packages. No heavy frameworks. Good choice for a single-binary CLI.

### Data Flow

1. **File Discovery** — `fast-glob` respects `.gitignore` + `.praxisignore` + `SKIP_DIRS`/`SKIP_EXTENSIONS`
2. **Recon** — `ReconAgent` maps tech stack (frameworks, languages) to optimize agent selection
3. **Parallel Scan** — 25 agents in chunks of 6, each with 30s timeout via `Promise.race`
4. **Shared Context** — `sharedFindings[]` allows cross-agent awareness (later agents see earlier findings)
5. **Dedup** — `file:line:rule` deduplication removes redundant findings
6. **Verification** — `VerifierAgent` checks surrounding code context, downgrades unconfirmed findings
7. **Deep Analysis** — Optional 3-tier LLM pipeline (Haiku triage → Sonnet analysis → Opus exploit-chain)
8. **Scoring** — 8 weighted categories, confidence-multiplied deductions → 0-100 score + A-F grade
9. **Standards Mapping** — Each finding tagged with control IDs from 8 frameworks

### Agent Framework

Every scanner extends `BaseAgent` which provides:

- `discoverFiles(rootPath)` — respects ignore patterns, size limits, skip lists
- `shouldRun(recon)` — agents can opt out for irrelevant projects
- `analyze(context)` — the main method subclasses must implement
- `createFinding({...})` — standardized finding factory

The `Orchestrator` coordinates execution:

- Per-agent timeouts (default 30s, configurable via `--timeout`)
- Parallel execution with configurable concurrency (default 6)
- `Promise.allSettled` — one agent failure doesn't crash the scan
- Shared context passing between agents

### Scoring Engine

8 categories aligned with OWASP Top 10 2025:

| Category | Weight | Max Deduction |
|---|---|---|
| Secrets | 15 | 15 |
| Code Vulnerabilities (injection) | 15 | 15 |
| Dependencies | 13 | 13 |
| Auth & Access Control | 15 | 15 |
| Configuration | 8 | 8 |
| Supply Chain | 12 | 12 |
| API Security | 10 | 10 |
| AI/LLM Security | 12 | 12 |

Confidence multipliers: `high: 1.0`, `medium: 0.6`, `low: 0.3`

Grade thresholds: A (90+), B (75+), C (60+), D (40+), F (<40)

### Threat Intel Pipeline

11 sources in two tiers:

**Free/Core (6):** OSV, GHSA, KEV, EPSS, NVD, Gitleaks
**Optional/Paid (5):** Snyk, Socket, GitGuardian, Sonatype, Phylum

Two-pass architecture:
1. **First pass** — parallel fetch of all sources except NVD
2. **Second pass** — NVD enrichment using CVEs collected in pass 1

Per-source TTL caching with stale-cache fallback on transient outages.

### LLM Provider Abstraction

Single abstraction over 5+ providers:

| Provider | Structured Output | Multi-tier | Streaming |
|---|---|---|---|
| Anthropic (Claude) | ✅ (tool-use) | ✅ (3-tier) | ✅ |
| OpenAI | ✅ (JSON mode) | ❌ | ✅ |
| Google (Gemini) | ❌ | ❌ | ❌ |
| Ollama (local) | ❌ | ❌ | ❌ |
| OpenAI-compatible | ❌ | ❌ | ❌ |

DeepAnalyzer 3-tier pipeline (Anthropic only):
- **Tier 1** (Haiku) — fast triage: skip / review / escalate
- **Tier 2** (Sonnet) — deep taint analysis with full file context
- **Tier 3** (Opus) — exploit-chain reasoning for confirmed critical findings

### Output Formatter Registry

Registry pattern in `cli/core/output/`:

| Format | Schema | Notes |
|---|---|---|
| JSON | `schemaVersion: 3` | Pretty-print default, compact option |
| SARIF | 2.1.0 | GitHub Code Scanning compatible |
| HTML | Styled report | Standalone file |
| CSV | Flat table | Spreadsheet import |
| Markdown | GitHub-friendly | Issue/PR ready |

### External Integrations

- **GitHub Action** — `action.yml` composite action (⚠️ stale: says "16 agents")
- **Claude Code Plugin** — `claude-code-plugin/` with skills
- **VS Code Extension** — `vscode-extension/`
- **MCP Server** — `praxis mcp` JSON-RPC server mode

---

## 2. Code Review Findings

### Critical Issues

| # | Severity | Finding | Location | Effort |
|---|---|---|---|---|
| 1 | **CRITICAL** | No CI workflow exists. README badge links to `ci.yml` that doesn't exist. No `.github/` directory. | Root | Small |
| 2 | **CRITICAL** | Plugin loader executes arbitrary JS with full process privileges. `IMPROVEMENT-PLAN.md` marks P-IMP-014 as `[x]` done, but code shows NO sandboxing. | `cli/utils/plugin-loader.js` | Medium |
| 3 | **HIGH** | `fix.js` is a basic secret scanner generating `.env.example`. NOT the LLM fix loop. Real fix loop is `agent-fix.js`. Naming is misleading. | `cli/commands/fix.js` | Medium |
| 4 | **HIGH** | `action.yml` says "16 AI security agents" but project has 25. Stale metadata. | `action.yml:2` | Trivial |

### Bugs & Edge Cases

| # | Severity | Finding | Location |
|---|---|---|---|
| 5 | **HIGH** | `runAgent()` timeout uses `setTimeout` that never clears — dangling timer after agent resolves. Memory leak on long runs. | `orchestrator.js:67-72` |
| 6 | **MEDIUM** | `discoverFiles()` calls `fs.statSync()` for EVERY file synchronously. Blocks event loop on large repos (10K+ files). | `base-agent.js:107-115` |
| 7 | **MEDIUM** | `loadCustomPatterns()` silently swallows parse errors. Malformed `.praxis.json` disables all custom patterns without clear warning. | `scan.js:40-55` |
| 8 | **MEDIUM** | `VerifierAgent` reads file content with `readFileSync` per finding. No caching — 10 findings in same file = 10 reads. | `verifier-agent.js` |
| 9 | **LOW** | `parseJSON()` silently returns `[]` on parse failure. Malformed LLM response drops ALL findings without warning. | `llm-provider.js:73-80` |
| 10 | **LOW** | `BUILT_IN_AGENTS` factory uses `new` on every call. Double `buildOrchestrator()` calls re-instantiate all 25 agents. | `agents/index.js:78-104` |

### Code Smells & Technical Debt

| # | Finding | Location |
|---|---|---|
| 11 | **Duplicated file discovery** — `scan.js`, `fix.js`, and `base-agent.js` all implement their own `findFiles()` | 3 files |
| 12 | **Inconsistent error handling** — some commands `process.exit(1)`, others throw. No unified error boundary. | Commands |
| 13 | **`fix.js` vs `agent-fix.js` naming** — backwards naming causes confusion | Commands |
| 14 | **Stale agent count** — `package.json` says "26", README says "25", `action.yml` says "16" | Multiple |
| 15 | **No input validation on `--base-url`** — user-supplied string passed to fetch. Potential SSRF. | `praxis.js` |
| 16 | **Hardcoded cost estimation** — assumes Haiku pricing even when using Opus ($15/1K input) | `deep-analyzer.js` |
| 17 | **No rate limiting on intel fetches** — parallel requests to all 11 sources may trigger rate limits | `intel/index.js` |
| 18 | **Hardcoded IOC lists** — `COMPROMISED_PACKAGES` in supply-chain agent will go stale | `supply-chain-agent.js` |

### Security Concerns

| # | Severity | Finding |
|---|---|---|
| 19 | **CRITICAL** | Plugin system has NO sandboxing. Malicious `.praxis/agents/*.js` runs with full Node.js privileges. |
| 20 | **HIGH** | `--base-url` allows arbitrary URL injection. Attacker-controlled URL can intercept LLM API keys. |
| 21 | **MEDIUM** | `parseJSON()` strips markdown fences but doesn't validate parsed structure. |
| 22 | **MEDIUM** | Secret patterns use `[\s\S]{0,500}` windows — potential ReDoS on crafted input. |

---

## 3. Feature Completeness

### Complete ✅

- 25 scanning agents (all real implementations)
- 11 threat intel sources with TTL caching
- 8 AI security standards mappers
- Multi-LLM provider abstraction (5 providers)
- Output formatter registry (JSON, SARIF, HTML, CSV, Markdown)
- Interactive fix loop with undo
- GitHub Action composite (`action.yml`)
- Plugin system for custom agents
- Cache manager for incremental scans
- Baseline comparison
- Git hooks integration

### Partially Implemented ⚠️

| Feature | Status | Gap |
|---|---|---|
| `--sandbox` fix verification | IMPROVEMENT-PLAN says `[x]` | Need to verify actual implementation |
| `praxis fix --ci` mode | IMPROVEMENT-PLAN says `[x]` | Need to verify |
| PDF report | Flag exists | Requires Chrome/Chromium, no fallback |
| Swarm mode (`--swarm`) | Flag exists | Untested end-to-end |
| `praxis mcp` server | Mentioned in docs | Completeness unverified |

### Missing Quality-of-Life

| Feature | Value | Effort |
|---|---|---|
| CI workflow (`.github/workflows/ci.yml`) | CRITICAL | Small |
| `praxis doctor` self-test | High | Small |
| Configuration file (`praxis.config.js`) | Medium | Medium |
| Exit code documentation | High | Small |

---

## 4. Testing Assessment

### Current Coverage

| File | What's Tested | Quality |
|---|---|---|
| `agents.test.js` | 7 agents (InjectionTester, AuthBypass, APIFuzzer, + 4) | ✅ Good positive + negative |
| `core.test.js` | fs.js, errors.js, output registry, JSON, branding | ✅ Solid |
| `intel.test.js` | Threat intel merge, cache, sources | ✅ |
| `standards.test.js` | Standards registry, mapping | ✅ |
| `model-file-scanner.test.js` | Model file scanning | ✅ |
| `prompt-injection-prober.test.js` | Prompt injection detection | ✅ |

### Critical Gaps

| Gap | Risk | Priority |
|---|---|---|
| No command-level tests | 38 commands have zero tests | CRITICAL |
| No orchestrator integration test | Parallel execution, dedup, timeout untested | HIGH |
| No fix loop test | `agent-fix.js` is untested | HIGH |
| No LLM provider test | Provider abstraction untested | HIGH |
| No output format tests (except JSON) | SARIF, HTML, CSV, Markdown untested | MEDIUM |
| No end-to-end test | Full scan→score→report pipeline untested | HIGH |
| No performance test | Large repo behavior unknown | MEDIUM |

---

## 5. Documentation Assessment

### Current State

| Doc | Status | Issues |
|---|---|---|
| `README.md` | ✅ Good | Agent count inconsistency, no screenshots |
| `CLAUDE.md` | ✅ Good | Accurate, comprehensive |
| `CHANGELOG.md` | ⚠️ Minimal | Only 2 entries (Unreleased + 1.0.0) |
| `docs/USAGE.md` | ⚠️ Exists | Not reviewed in depth |
| `docs/THREAT_INTEL.md` | ⚠️ Exists | Not reviewed in depth |
| `docs/IMPROVEMENT-PLAN.md` | ✅ Excellent | Self-aware, tracked |
| `action.yml` | ⚠️ Stale | Says "16 agents" |

### Missing Documentation

| Gap | Priority |
|---|---|
| `.github/CONTRIBUTING.md` | HIGH |
| `.github/SECURITY.md` | HIGH |
| `.github/CODE_OF_CONDUCT.md` | MEDIUM |
| Architecture diagram (visual) | MEDIUM |
| Agent development guide | HIGH |
| Configuration reference (all flags, env vars) | HIGH |
| Troubleshooting guide | MEDIUM |
| Screenshots/GIFs of scan output | HIGH |
| Comparison table vs Semgrep/Bearer/Trivy | MEDIUM |

---

## 6. Release Readiness Scorecard

| Category | Score | Notes |
|---|---|---|
| Installation | 8/10 | `npm install` works, minimal deps |
| Usability | 7/10 | Good CLI help, `fix` vs `agent-fix` confusion |
| Reliability | 5/10 | No CI, incomplete tests, untested edge cases |
| Documentation | 6/10 | README good, missing community files |
| Maintainability | 8/10 | Clean architecture, consistent patterns, ESM |
| Test Coverage | 4/10 | 6 test files for 38+ commands |
| Security | 5/10 | Plugin sandboxing claimed but not implemented |
| Polish | 6/10 | Stale counts, broken badge, placeholder URLs |

**Overall: 62/100 — Not ready for public release.**

---

## 7. Prioritized Implementation Backlog

### Phase 1 — Release Blockers (1-2 days)

1. Create `.github/workflows/ci.yml` (test + lint + dogfood)
2. Fix agent count inconsistencies across all files
3. Fix `action.yml` stale description
4. Add `CONTRIBUTING.md` + `SECURITY.md`

### Phase 2 — Hardening (3-5 days)

5. Implement plugin sandboxing (`node:vm` or manifest verification)
6. Add smoke tests for all 38 commands
7. Fix timeout timer leak in orchestrator
8. Replace `statSync` with async stat in file discovery
9. Add `praxis doctor` self-test

### Phase 3 — Polish (2-3 days)

10. Rename `fix.js` → `env-fix.js` or document the difference
11. Add screenshots/GIFs to README
12. Add comparison table vs alternatives
13. Write agent development guide
14. Add configuration reference

### Phase 4 — Testing (3-5 days)

15. Integration test: full scan→score→report pipeline
16. Integration test: fix loop end-to-end
17. Performance test: 50K+ file repo
18. Negative tests: malformed input, missing files, no network
19. Test all output formatters (SARIF, HTML, CSV, Markdown)

### Phase 5 — Post-Release

20. Publish to npm
21. Set up Dependabot/Renovate
22. Add issue/PR templates
23. Write blog post announcing launch

---

## 8. Showcase Assessment

### Portfolio Value

| Audience | Verdict | Why |
|---|---|---|
| Recruiters | ✅ Yes | Unique niche (AI security), clean code, MIT license |
| Hiring Managers | ⚠️ Maybe | Strong architecture, but missing CI/tests weakens "production-ready" |
| Senior Engineers | ✅ Yes | Agent framework well-designed, intel pipeline real, fix loop impressive |
| Security Professionals | ✅ Yes | Genuine AI-security coverage gap filler |
| OSS Maintainers | ⚠️ Maybe | Good code, missing community infrastructure |

### What's Missing for Strong Showcase

1. **Demo GIF/video** — scan running, findings appearing, fix loop in action
2. **Live example output** — paste actual scan output in README
3. **Benchmark comparison** — Praxis vs npm audit vs Semgrep on same repo
4. **Real-world case study** — "Praxis found X vulnerabilities in Y project"
5. **Architecture diagram** — visual, not just Mermaid
6. **Test coverage badge** — once CI exists
7. **npm download badge** — once published

---

## Key Architectural Decisions (Validated)

| Decision | Verdict | Rationale |
|---|---|---|
| ESM-only (`"type": "module"`) | ✅ Correct | Modern Node.js, tree-shaking, future-proof |
| Minimal dependencies (5 runtime) | ✅ Excellent | Small attack surface, fast install, no bloat |
| Agent-per-file pattern | ✅ Excellent | Easy to add/remove agents, clear ownership |
| Registry pattern for outputs/standards | ✅ Excellent | Extensible without modifying core |
| Regex-based detection (not AST) | ✅ Correct for scope | AST/dataflow would add massive dependency bloat |
| Offline-first with optional LLM | ✅ Excellent | Privacy-preserving, works air-gapped |
| Per-agent timeout + parallel chunks | ✅ Good | Prevents one slow agent from blocking |
| Two-pass intel (NVD enrichment) | ✅ Smart | NVD needs CVE list from other sources |
| 3-tier LLM analysis (Anthropic) | ✅ Excellent | Cost-efficient triage before expensive analysis |
| Atomic file writes | ✅ Correct | No mid-write corruption |

## Deferred Decisions (Correctly Deferred)

| Decision | Why Deferred | Verdict |
|---|---|---|
| AST/dataflow backend | Massive dependency bloat for single-binary CLI | ✅ Correct |
| Multi-language fix support (Go, Rust) | Needs AST awareness first | ✅ Correct |
| Semgrep-compatible rule format | Praxis rules run arbitrary JS — not translatable to static YAML | ✅ Correct |
| Non-AI vuln coverage parity | Moat is AI-security, not general SAST | ✅ Correct |

---

## Final Word

Praxis is a genuinely innovative project. The architecture is sound, the problem space is real, and the execution is solid. The gap between "solid beta" and "release-ready" is mostly operational hygiene — CI, tests, documentation infrastructure.

The IMPROVEMENT-PLAN.md already shows excellent self-awareness. The key insight is that **detection depth** (AST/dataflow) is correctly deferred — trying to build a full compiler engine inside a single-binary ESM CLI would be scope death. The moat is AI-security coverage, not general SAST parity.

Focus on the release blockers first. Get CI green, fix the badge, add the community files. Then ship with confidence.
