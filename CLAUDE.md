# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Praxis is a single-binary, AI-native security CLI written in pure ESM Node.js (≥18). The product is a tight find→fix→verify loop: scan a codebase with 25 parallel agents, draft LLM-guided remediations, ask the user, apply atomically, re-scan, and keep an undo log. There is no build step — the CLI runs directly from source via `cli/bin/praxis.js`.

There are three distribution surfaces wrapping the same code:
- The npm package (binary `praxis`, see `package.json` `bin`).
- A composite GitHub Action (`action.yml`) that installs the package and runs `praxis ci`.
- A Claude Code plugin under `claude-code-plugin/` exposing skills like `praxis-scan`, `praxis-fix`, etc.

## Commands

```bash
npm install                                    # install deps
npm test                                       # node:test suite (cli/__tests__)
npm run lint                                   # eslint flat config (cli/**)
npm run praxis -- <args>                       # run the CLI from source
node cli/bin/praxis.js <args>                  # same, no npm wrapper
node cli/bin/praxis.js scan .                  # full audit on the repo itself

# Run a single test file
node --test cli/__tests__/intel.test.js
node --test cli/__tests__/agents.test.js
node --test cli/__tests__/core.test.js

# Run a single test by name (node:test filter)
node --test --test-name-pattern="validatePath" cli/__tests__/core.test.js
```

CI (`.github/workflows/ci.yml`) runs the test suite on Node 18/20/22, then dogfoods Praxis on itself with `node cli/bin/praxis.js scan .` — keep that command green.

The `npm test` script lists test files explicitly. New test files under `cli/__tests__/` must be added to the `test` script in `package.json` to run in CI.

## Architecture

### Command surface (`cli/bin/praxis.js`)

The user-facing CLI is `commander`-based and reorganized into six verb-led groups so `--help` builds a quick mental model: `scan`, `fix`, `agents`, `intel`, `report`, `project`, plus three top-level shortcuts (`vibe`, `score`, no-arg REPL). Each subcommand is a thin wrapper that imports from `cli/commands/*.js`. Adding a flag = edit the relevant `program.command(...)` block in `cli/bin/praxis.js` AND the implementation in `cli/commands/<name>.js`.

`cli/index.js` is a separate programmatic-API export surface (used by the Claude Code plugin and external integrations). When you add a command or agent that should be importable, re-export it there too.

### Agent framework (`cli/agents/`)

This is the core of the product. Every scanner is a class extending `BaseAgent` (`cli/agents/base-agent.js`), which provides:
- `discoverFiles(rootPath)` — respects `SKIP_DIRS`, `SKIP_EXTENSIONS`, `.gitignore`, and `.praxisignore`.
- `scanFileWithPatterns(file, patterns)` — produces `Finding` objects via `createFinding({...})`.
- `shouldRun(recon)` — agents can opt out for irrelevant projects (e.g. `MobileScanner` skips non-mobile repos).

`Orchestrator` (`cli/agents/orchestrator.js`) runs registered agents in parallel chunks (default concurrency 6, default per-agent timeout 30s), with a shared `context` so later agents can read findings from earlier agents (`sharedFindings`). After the parallel pass it: deduplicates (`file:line:rule`), runs `VerifierAgent` (downgrades suspected false positives), optionally runs `DeepAnalyzer` (LLM taint analysis, opt-in via `--deep`), tunes confidence (test/doc/example paths get downgraded), then sorts by severity.

`buildOrchestrator()` and `buildOrchestratorAsync(rootPath)` in `cli/agents/index.js` are the wiring points — the async variant additionally loads user plugins from `<rootPath>/.praxis/agents/*.js` via `cli/utils/plugin-loader.js`.

**Adding an agent**: create `cli/agents/your-agent.js` extending `BaseAgent`, register it in the `BUILT_IN_AGENTS` array in `cli/agents/index.js`, and add a smoke test under `cli/__tests__/agents.test.js`. Use `createFinding(...)` so the shape stays consistent.

### Threat intel system (`cli/utils/intel/`)

Multi-source feed at `~/.praxis/threat-intel.json` (location overrideable via `HOME`/`USERPROFILE`, which is how the tests sandbox state). Six core sources (OSV, GHSA, KEV, EPSS, NVD, Gitleaks) and five optional paid sources are each an ES module under `cli/utils/intel/sources/` exporting `name`, `tier`, `description`, optional `envKey`, `TTL`, and `fetchAll()`. `runUpdate()` in `index.js` does parallel fetch + per-source TTL'd cache, with NVD as a second pass enriched by CVEs collected in pass 1. `merge.js` joins everything into a unified schema (`osvIndex`, `ghsaIndex`, `cveAdvisories[]`, `kevList`, `epssScores`, `secretRules`).

The runtime query API is `ThreatIntel` in `cli/utils/threat-intel.js` — agents call `lookupOsv`, `getEpss`, `isInKev`, etc. It lazy-loads the merged feed and falls back to the bundled seed at `cli/data/threat-intel.json` when nothing is on disk yet.

Adding a source: drop a module in `cli/utils/intel/sources/`, register in `ALL_SOURCES` in `cli/utils/intel/index.js`, and (if it should populate a known index) add a case in `cli/utils/intel/merge.js`. See `docs/THREAT_INTEL.md` for the full reference.

### AI-security standards (`cli/utils/standards/`)

Mirrors the intel-sources pattern. Each standard (OWASP LLM Top 10, MITRE ATLAS, NIST AI 600-1, AVID, OWASP ML Top 10, EU AI Act, ISO/IEC 42001, Google SAIF) is a module under `cli/utils/standards/sources/` exporting `name`, `version`, `title`, `controls[]`, and a pure `mapFinding(finding)` mapper. The registry in `cli/utils/standards/index.js` exposes `mapFindingToStandards`, `getStandardsSummary`, and `getStandard`.

`scoring-engine.js` calls `mapFindingToStandards` post-creation so every finding carries a `standards` field; the report carries a top-level `standardsSummary`. SARIF embeds it under `result.properties.standards`. The `praxis scan standard <name> .` subcommand filters findings to one standard. This is parallel to (not a replacement for) `cli/utils/compliance-map.js`, which still owns Agentic Top 10 / SOC2 / ISO27001 / NIST AI RMF mappings.

### Output formatters (`cli/core/output/`)

A registry pattern — `render(format, report)` in `cli/core/output/index.js` dispatches to `json.js`, `sarif.js`, etc. Add a new output by writing `your-format.js` exporting `default function(report, options): string` and adding it to `REGISTRY`. Don't reintroduce per-command switch statements — the registry replaced four duplicated implementations.

### Core utilities (`cli/core/`)

`cli/core/fs.js` (`validatePath`, `validateDir`, `ensureDir`) replaced 16+ duplicated copies of `path.resolve + fs.existsSync` logic across commands. Use these in any new command.

### LLM providers (`cli/providers/llm-provider.js`)

Single abstraction over Anthropic, OpenAI, Google, Ollama, and any OpenAI-compatible endpoint (Groq, Together, LM Studio, etc.). Auto-detects from env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_AI_API_KEY`, `MOONSHOT_API_KEY`...). All `--deep`, `--think`, `--budget` flags flow through this layer.

## Conventions

- **ESM throughout** (`"type": "module"` in `package.json`). Use `import`/`export`, no `require`.
- 2-space indent, single quotes, semicolons. eslint flat config in `eslint.config.js` — `npm run lint` is the source of truth.
- Tests use `node:test` and live under `cli/__tests__/`. They sandbox state by overriding `HOME`/`USERPROFILE`.
- Prefer extending the registries (`cli/agents/index.js`, `cli/core/output/index.js`, `cli/utils/intel/index.js`, `cli/utils/standards/index.js`) over inlining code paths in commands. `.github/CONTRIBUTING.md` explicitly calls this out.
- User-facing docs live in `docs/` (USAGE.md, THREAT_INTEL.md). Governance / community-health files live in `.github/` (CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md) so GitHub auto-detects them. Top level keeps only README, CHANGELOG, CLAUDE, LICENSE.
- `praxis-ignore` inline comment suppresses a finding on that line — keep this convention when writing examples or test fixtures that would otherwise trip an agent.
- One change per pull request; reasoning in the description, not just the diff.

## Quirks worth knowing

- Running the CLI with no args on a TTY drops into the interactive REPL (`shellCommand` in `cli/commands/shell.js`); with no args and no TTY it prints quick-start help.
- Plugin auto-discovery requires the async builder. If you wire a code path directly through the synchronous `buildOrchestrator()`, user plugins from `.praxis/agents/` will be invisible — use `buildOrchestratorAsync(rootPath)` whenever a `rootPath` is available.
- The orchestrator's `tuneConfidence` automatically lowers severity in test/doc/example paths and on comment lines. If you write security tests that include realistic-looking secrets/payloads, this is what keeps them from showing up as findings — but don't rely on it for files outside those path patterns.
- `npm test` enumerates test files explicitly in the `test` script. Add new test files there, or they won't run in CI.
