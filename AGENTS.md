# AGENTS.md — Praxis

> **For AI agents and human contributors** (a `CLAUDE.md` also exists; `AGENTS.md` is the cross-agent standard).

## What this is

Praxis is a single-binary, AI-native security CLI in pure ESM Node.js (≥18): a tight **find→fix→verify** loop that scans a codebase with 28 parallel agents, drafts LLM-guided remediations, asks the user, applies atomically, re-scans, and keeps an undo log. No build step — runs from source via `cli/bin/praxis.js`. Distribution surfaces: npm package (`praxis`), GitHub Action (`action.yml`), Claude Code plugin (`claude-code-plugin/`).

## Quick commands

```bash
npm install && npm test && npm run lint
node cli/bin/praxis.js scan .   # dogfood (CI runs this — keep it green)
```

New test files under `cli/__tests__/` **must** be added to the `test` script in `package.json` or they won't run in CI.

## Conventions

- ESM throughout, 2-space indent, single quotes; `npm run lint` is the source of truth.
- Extend the registries instead of inlining code paths in commands:
  - `cli/agents/index.js` — add a scanner by extending `BaseAgent`
  - `cli/core/output/index.js` — add an output formatter
  - `cli/utils/intel/index.js` — add a threat-intel source
  - `cli/utils/standards/index.js` — add a standards mapper
  - `cli/utils/mcp-trust.js` — MCP trust registry lookups (update `cli/data/known-mcps.json` + its embedded SHA-256 together)
- Use `cli/core/fs.js` (`validatePath` / `validateDir` / `ensureDir`) — they replaced 16+ duplicated copies.
- One change per PR; reasoning in the description, not just the diff.
- Agent framework: scanners extend `BaseAgent` (`cli/agents/base-agent.js`); register in `BUILT_IN_AGENTS` (`cli/agents/index.js`) + smoke test (`cli/__tests__/agents.test.js`), then update the agent count everywhere it appears (`cli/core/branding.js`, `cli/utils/output.js`, `action.yml`, `claude-code-plugin/`, `vscode-extension/package.json`, `docs/USAGE.md`, `README.md`).
- Post-processors (like `VerifierAgent`, `DeepAnalyzer`, and the governance absence-audits in `cli/agents/governance-audits.js`) are NOT in the agent pool — wire them in `cli/agents/orchestrator.js`.
- Knowledge lives in data, not code:
  - `cli/data/probes/prompt-injection-corpus.json` — probe signatures (own phrasing only; ReDoS guard enforced at compile; bump `version` + `_refresh_policy.lastReviewed` on change)
  - `cli/data/atlas-knowledge.json` — vendored MITRE ATLAS snapshot (see `cli/utils/standards/atlas-knowledge.js` for hydration; keep the `_attribution` block)
  - `cli/data/eaa-catalog.json` — CC0 EAA technique catalog backing `EndpointAgentAbuseAgent`
  - `cli/data/known-mcps.json` — MCP trust registry (SHA-256 in `mcp-trust.js` must match)
- Vendored data obligations live in `docs/THIRD_PARTY_NOTICES.md` — update it whenever a data asset is added or re-synced.
- Secret-redaction invariant: raw matched secret values must never appear in report output — the renderers in `cli/core/output/` redact centrally; keep the invariant test green (`cli/__tests__/agents.test.js`).

## Workspace rigor (umbrella — applies to all CADRE-Platform projects)

> Gist: **evidence-before-claims · no fabrication · multi-stage gates · human-approval boundary · target-as-data · honest reporting · verify-before-agreeing.** When developing inside the CADRE umbrella workspace, the full contract is at `../CADRE/docs/internal/workspace-rigor-contract.md` (local-only; not part of this repository).
