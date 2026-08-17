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
- Extend the registries (`cli/agents/index.js`, `cli/core/output/index.js`, `cli/utils/intel/index.js`, `cli/utils/standards/index.js`) instead of inlining code paths in commands.
- Use `cli/core/fs.js` (`validatePath` / `validateDir` / `ensureDir`) — they replaced 16+ duplicated copies.
- One change per PR; reasoning in the description, not just the diff.
- Agent framework: scanners extend `BaseAgent` (`cli/agents/base-agent.js`); register in `BUILT_IN_AGENTS` (`cli/agents/index.js`) + smoke test (`cli/__tests__/agents.test.js`).

## Workspace rigor (umbrella — applies to all CADRE-Platform projects)

> Full contract (local-only): `../CADRE/docs/internal/workspace-rigor-contract.md`. Gist: **evidence-before-claims · no fabrication · multi-stage gates · human-approval boundary · target-as-data · honest reporting · verify-before-agreeing.** Umbrella pointer: `../CADRE/docs/internal/ACTIVE.md`.
