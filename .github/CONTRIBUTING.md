# Contributing to Praxis

Thanks for considering a contribution. Praxis is a single-binary, AI-native
security CLI — ESM Node.js ≥18, no build step, runs from source.

## Quick start

```bash
npm install
npm test
npm run lint
node cli/bin/praxis.js scan .   # dogfood — CI runs this, keep it green
```

New test files under `cli/__tests__/` **must** be added to the `test` script in
`package.json`, or CI will never run them.

## Conventions

- ESM throughout, 2-space indent, single quotes. `npm run lint` is the source
  of truth (0 errors; warnings are reviewed case-by-case).
- Extend the registries instead of inlining code paths in commands:
  - `cli/agents/index.js` — add a scanner by extending `BaseAgent`
  - `cli/core/output/index.js` — add an output formatter
  - `cli/utils/intel/index.js` — add a threat-intel source
  - `cli/utils/standards/index.js` — add a standards mapper
- Use `cli/core/fs.js` (`validatePath` / `validateDir` / `ensureDir`) for path
  handling.
- One change per PR; explain the reasoning in the description, not just the
  diff.
- CLI commands are registered in `cli/bin/praxis.js`. Top-level legacy aliases
  live there too — keep them in sync with their grouped counterparts.

## Authoring a new agent

1. Create `cli/agents/<your-agent>.js` extending `BaseAgent` (see
   `cli/agents/base-agent.js` for the finding shape and `shouldRun` contract).
2. Register it in `BUILT_IN_AGENTS` (`cli/agents/index.js`).
3. Add a smoke test in `cli/__tests__/agents.test.js` (positive + negative
   case) and wire it into `package.json` if it is a new test file.
4. Update the agent table in `README.md` and the agent count everywhere it
   appears (`cli/core/branding.js`, `cli/utils/output.js`, `action.yml`,
   `claude-code-plugin/`, `vscode-extension/package.json`, `docs/USAGE.md`).

## Tests

```bash
npm test                          # node --test, ~210 cases
node cli/bin/praxis.js scan .     # dogfood self-scan
```

## Security

Found a vulnerability? See `.github/SECURITY.md` — do not open a public issue
for active exploits.
