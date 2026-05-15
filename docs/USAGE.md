# Praxis — Complete Usage Guide

AI-native security CLI for AI-augmented codebases. Single binary, find→fix→verify
loop on autopilot. 25 parallel security agents (23 built-in + ModelFileScanner +
PromptInjectionProber), multi-source threat intel, modular alignment with 8 AI-security
standards, LLM-powered remediation with diff review and undo log. Works fully
offline; LLM features are optional.

---

## Table of contents

1. [Install](#install)
2. [Quick start](#quick-start)
3. [Command groups overview](#command-groups-overview)
4. [`praxis scan` — security scans](#praxis-scan--security-scans)
5. [`praxis fix` — apply remediations](#praxis-fix--apply-remediations)
6. [`praxis agents` — AI agent surface](#praxis-agents--ai-agent-surface)
7. [`praxis intel` — threat intelligence](#praxis-intel--threat-intelligence)
8. [`praxis report` — format/share results](#praxis-report--formatshare-results)
9. [`praxis project` — setup & state](#praxis-project--setup--state)
10. [Top-level shortcuts](#top-level-shortcuts)
11. [AI security standards alignment](#ai-security-standards-alignment)
12. [Environment variables](#environment-variables)
13. [Configuration files](#configuration-files)
14. [Output formats](#output-formats)
15. [CI/CD integration](#cicd-integration)
16. [Custom plugins](#custom-plugins)
17. [Troubleshooting](#troubleshooting)

---

## Install

```bash
# From source (this repo)
npm install
npm link                         # exposes `praxis` globally

# Or run directly without linking
node cli/bin/praxis.js --help
```

Requires Node.js ≥ 18. No build step — Praxis runs from source via the `bin`
entry in `package.json`.

---

## Quick start

```bash
praxis scan .                    # Full audit: secrets + 25 agents + deps + score
praxis fix .                     # Interactive LLM-guided fixes
praxis agents audit .            # Audit CLAUDE.md, .cursorrules, MCP, skills
praxis intel update              # Refresh threat-intel feed
praxis project init              # Add security configs to your project
praxis vibe .                    # Emoji-graded A–F score
praxis --help                    # Show all groups
```

Running `praxis` with no args on a TTY drops into the interactive REPL.

---

## Command groups overview

| Group | Purpose |
| --- | --- |
| `scan` | Run security scans |
| `fix` | Apply remediations |
| `agents` | Audit the AI/agent surface (skills, MCP, configs, attestation, BOM) |
| `intel` | Threat-intelligence feed updates and advisory operations |
| `report` | Format, diff, or share existing scan results |
| `project` | Init, hooks, watch, doctor, baseline, plugins, policies |

Plus three top-level shortcuts: `praxis vibe`, `praxis score`, and `praxis` alone (REPL on a TTY).

---

## `praxis scan` — security scans

### `scan full [path]` (default)

Full audit: secrets + 25 agents + deps + score + remediation plan.

| Flag | Description |
| --- | --- |
| `--json` | Output results as JSON |
| `--sarif` | Output as SARIF 2.1.0 |
| `--csv` | Output as CSV |
| `--md` | Output as Markdown |
| `--html [file]` | HTML report path (default: `praxis-report.html`) |
| `--pdf [file]` | Generate PDF (requires Chrome/Chromium) |
| `--compare` | Detailed comparison with last scan |
| `--timeout <ms>` | Per-agent timeout in ms (default 30000) |
| `--no-deps` | Skip dependency audit |
| `--no-ai` | Skip AI classification |
| `--no-cache` | Force full rescan |
| `--baseline` | Only show findings not in the baseline |
| `--deep` | LLM-powered taint analysis for critical/high findings |
| `--think` | Enable extended thinking mode |
| `--local` | Use local Ollama for deep analysis |
| `--model <model>` | LLM model for deep/AI analysis |
| `--provider <name>` | LLM provider (anthropic/openai/google/ollama/openai-compatible) |
| `--base-url <url>` | Custom OpenAI-compatible endpoint |
| `--budget <cents>` | Max spend in cents for deep analysis (default 50) |
| `--verify` | Check if leaked secrets are still active |
| `--include-legal` | Also run the legal risk scan |
| `--agentic [iterations]` | Agentic scan→fix→verify loop |
| `--agentic-target <score>` | Target security score for agentic loop |
| `--hermes-only` | Run only Hermes-relevant agents |
| `--fail-below <threshold>` | Exit 1 if score < threshold |
| `-v, --verbose` | Verbose output |

### `scan secrets [path]`

Fast pattern-based secret scan only (no agents).

| Flag | Description |
| --- | --- |
| `-v, --verbose` | Show all files being scanned |
| `--no-color` | Disable colored output |
| `--json` | JSON output |
| `--sarif` | SARIF output |
| `--include-tests` | Also scan test files |
| `--no-cache` | Force full rescan |

### `scan changed [ref]`

Scan only files changed since `<ref>` (default: `HEAD`).

| Flag | Description |
| --- | --- |
| `--staged` | Scan only staged changes |
| `--json` | JSON output |
| `-p, --path <path>` | Project path (default: cwd) |
| `--timeout <ms>` | Per-agent timeout in ms |

### `scan env [path]`

Credential health check: `.env` coverage, source cross-ref, git history.

| Flag | Description |
| --- | --- |
| `--json` | JSON output |

### `scan redteam [path]`

22 adversarial agents in parallel — 80+ attack classes.

| Flag | Description |
| --- | --- |
| `--agents <list>` | Comma-separated list of agents |
| `--json` | JSON output |
| `--sarif` | SARIF output |
| `--html [file]` | Generate HTML security report |
| `--sbom [file]` | Generate CycloneDX SBOM |
| `--no-deps` | Skip dependency audit |
| `--no-ai` | Skip AI classification |
| `--deep` | LLM-powered taint analysis |
| `--swarm` | AI swarm mode — 23 parallel agents via DeepSeek/Kimi |
| `--think`, `--local`, `--model`, `--provider`, `--base-url`, `--budget` | LLM controls (same as `scan full`) |
| `-v, --verbose` | Verbose output |

### `scan standard [name] [path]`

Filter findings by AI-security standard. **New in this release.**

| Flag | Description |
| --- | --- |
| `--list` | List available standards and exit |
| `--control <id>` | Filter to a single control (e.g. `LLM01`) |
| `--json` | JSON output |
| `--sarif` | SARIF output |
| `--format <name>` | Output format from registry (json/sarif) |

Standards available: `owasp-llm`, `mitre-atlas`, `nist-ai-600-1`, `avid`,
`owasp-ml`, `eu-ai-act`, `iso-42001`, `google-saif`. See
[AI security standards alignment](#ai-security-standards-alignment).

### `scan ci [path]`

CI/CD pipeline mode: scan, score, exit 1 on failure.

| Flag | Description |
| --- | --- |
| `--threshold <score>` | Minimum passing score (default 75) |
| `--fail-on <severity>` | Fail on findings ≥ this severity |
| `--sarif <file>` | Write SARIF for GitHub Code Scanning |
| `--json` | JSON output |
| `--no-deps` | Skip dependency audit |
| `--baseline` | Only check new findings |
| `--github-pr` | Post findings as a GitHub PR comment |
| `--strict-intel` | Fail if threat-intel feed is stale |
| `--max-intel-age <duration>` | Max acceptable intel age (default `7d`) — accepts `7d`/`24h`/`30m`/`60s` |

---

## `praxis fix` — apply remediations

### `fix interactive [path]` (default)

Interactive LLM-guided: scan → plan → diff → ask → apply → verify.

| Flag | Description |
| --- | --- |
| `--plan-only` | Generate plans for review but never write |
| `--severity <level>` | Minimum severity to fix (default `low`) |
| `--provider <name>` | LLM provider |
| `--model <model>` | Specific model name |
| `--think` | Enable extended thinking |
| `--allow-dirty` | Allow running with uncommitted changes |
| `--branch [name]` | Create a branch and commit one fix per file |
| `--pr` | Push branch + open PR via `gh` (requires `--branch`) |
| `--yolo` | Auto-accept every plan (dangerous) |
| `--auto-low` | Auto-accept plans marked `risk:low` |
| `--sandbox` | Verify each fix in a Docker sandbox |

### `fix quick [path]`

Deterministic secret fixer: rewrite source + write `.env`. No LLM.

| Flag | Description |
| --- | --- |
| `--dry-run` | Preview without writing |
| `--yes` | Apply all fixes without prompting |
| `--stage` | Run `git add` on modified files |
| `--all` | Also fix common agent findings (debug, TLS bypass, shell injection) |

### `fix from-report [path]`

Apply LLM fixes from a deep-analysis JSON report and open a PR.

| Flag | Description |
| --- | --- |
| `--report <file>` | Path to praxis JSON report |
| `--severity <level>` | Minimum severity to fix |
| `--dry-run` | Preview without applying |
| `--yes` | Skip confirmation |

### `fix rotate [path]`

Open provider dashboards to revoke exposed secrets.

| Flag | Description |
| --- | --- |
| `--provider <name>` | Only rotate secrets for a specific provider |
| `--plan <file>` | Execute a rotation plan |

### `fix undo [path]`

Revert the last interactive fix (or all with `--all`).

| Flag | Description |
| --- | --- |
| `--all` | Revert every fix in the log |
| `--dry-run` | Show what would be reverted |

### `fix env-template`

Generate a `.env.example` with placeholder values from found secrets.

| Flag | Description |
| --- | --- |
| `--dry-run` | Preview without writing |

---

## `praxis agents` — AI agent surface

### `agents audit [path]` (default)

Audit AI agent configs (CLAUDE.md, .cursorrules, MCP servers, skills).

| Flag | Description |
| --- | --- |
| `--fix` | Auto-harden agent configurations |
| `--preflight` | Exit non-zero on critical findings (for CI) |
| `--red-team` | Simulate adversarial attacks against agent configs |
| `--json` | JSON output |

### `agents skill [target]`

Vet an AI agent skill (URL or path) before installing it.

| Flag | Description |
| --- | --- |
| `--all` | Scan all skills defined in `openclaw.json` |
| `--json` | JSON output |

### `agents mcp [target]`

Vet an MCP server's tool manifest before connecting.

| Flag | Description |
| --- | --- |
| `--json` | JSON output |

### `agents bom [path]`

Generate Agent Bill of Materials (CycloneDX ABOM).

| Flag | Description |
| --- | --- |
| `-o, --output <file>` | Output file path (default `abom.json`) |
| `--json` | Output to stdout as JSON |

### `agents serve`

Start praxis as an MCP server (Claude Desktop, Cursor, Windsurf).

---

## `praxis intel` — threat intelligence

### `intel update`

Refresh OSV, GHSA, KEV, EPSS, NVD, Gitleaks (+optional paid sources).

| Flag | Description |
| --- | --- |
| `--only <sources>` | Comma-separated subset (e.g. `osv,kev,epss`) |
| `--force` | Ignore per-source TTL caches |
| `--list` | Print available sources and exit |

### `intel deps [path]`

Audit deps via package manager (npm/yarn/pnpm/pip-audit/bundler-audit).

| Flag | Description |
| --- | --- |
| `--fix` | Run package manager fix command after auditing |

### `intel advisories [path]`

Check deps against live advisory feeds (OSV.dev, GitHub Advisories).

| Flag | Description |
| --- | --- |
| `--ecosystem <type>` | Filter by ecosystem (`npm`, `PyPI`) |
| `--json` | JSON output |

---

## `praxis report` — format/share results

### `report team [file]`

Convert Hermes Agent team output into a Praxis report.

| Flag | Description |
| --- | --- |
| `--html [path]` | Save as HTML report |
| `--json` | JSON output |

### `report legal [path]`

Legal risk audit: DMCA, leaked-source derivatives, IP disputes.

| Flag | Description |
| --- | --- |
| `--json` | JSON output |

### `report checklist`

Run the launch-day security checklist interactively.

| Flag | Description |
| --- | --- |
| `--no-interactive` | Print checklist without prompts |

### `report sbom [path]`

Generate Software Bill of Materials (CycloneDX SBOM).

| Flag | Description |
| --- | --- |
| `-o, --output <file>` | Output file path (default `sbom.json`) |

### `report benchmark [path]`

Compare your security score against industry averages.

| Flag | Description |
| --- | --- |
| `--json` | JSON output |

---

## `praxis project` — setup & state

### `project init`

Initialize security configs in your project.

| Flag | Description |
| --- | --- |
| `-f, --force` | Overwrite existing files |
| `--gitignore` | Only copy `.gitignore` |
| `--headers` | Only copy security headers config |
| `--agents` | Only add security rules to AI agent instruction files |
| `--openclaw` | Generate a hardened `openclaw.json` template |
| `--hermes` | Bootstrap Hermes Agent security config |
| `--from <url>` | Fetch a pre-built Hermes config bundle from a setup URL |

### `project doctor`

Diagnose environment: Node.js, git, API keys, cache, dependencies.

### `project hooks [action]`

Manage Claude Code hooks — real-time security gate on tool calls.

### `project guard [action]`

Install pre-commit/pre-push git hook to block secret commits.

| Flag | Description |
| --- | --- |
| `--pre-commit` | Install as pre-commit hook (instead of pre-push) |
| `--generate-hooks` | Generate defensive Claude Code hooks |

### `project watch [path]`

Continuous monitoring: watch files for security issues in real-time.

| Flag | Description |
| --- | --- |
| `--poll` | Use polling mode |
| `--configs` | Watch only agent config files |
| `--deep` | Run full agent scanning on changes |
| `--stateful` | Keep Kimi K2.6 conversation context between scans |
| `--model <model>` | LLM model for stateful watch |
| `--provider <name>` | LLM provider for stateful watch |
| `--status` | Show current watch status and exit |
| `--threshold <score>` | Alert when score drops below threshold |
| `--debounce <ms>` | Debounce interval in ms |
| `--slack [webhook]` | Post findings to Slack webhook |
| `--pr-comment` | Post inline findings as GitHub PR review comments |

### `project baseline [path]`

Create/manage a findings baseline — only report new findings.

| Flag | Description |
| --- | --- |
| `--diff` | Show what changed since baseline |
| `--clear` | Remove the baseline |

### `project memory [subcommand]`

Manage false-positive memory. Subcommands: `list`, `forget <key>`, `clear`.

### `project playbook [subcommand]`

Manage repo-specific LLM context playbook. Subcommands: `show`, `add-note "text"`.

### `project plugins [action]`

Manage custom security agent plugins from `.praxis/agents/`. Action `new <name>` scaffolds a new plugin.

### `project policy <action>`

Manage security policies. Action `init` creates a `.praxis.policy.json` template.

---

## Top-level shortcuts

### `praxis vibe [path]`

Vibe-graded security score with emoji and shareable badge.

| Flag | Description |
| --- | --- |
| `--badge` | Generate a shields.io markdown badge |

### `praxis score [path]`

Compute a 0–100 security health score.

| Flag | Description |
| --- | --- |
| `--no-deps` | Skip dependency audit |

### `praxis` (no args)

- On a TTY → drops into the interactive REPL.
- Otherwise → prints quick-start help.

---

## AI security standards alignment

Every finding is auto-tagged with all applicable AI-security standards. Reports
include a per-standard coverage summary.

| Standard | Module name | Controls |
| --- | --- | --- |
| OWASP Top 10 for LLM Applications (2025) | `owasp-llm` | LLM01–LLM10 |
| MITRE ATLAS | `mitre-atlas` | AML.T0010, T0018, T0024, T0034, T0040, T0043, T0048, T0051, T0053, T0054, T0057, T0070 |
| NIST AI 600-1 (Generative AI Profile) | `nist-ai-600-1` | GV/MP/MS/MG actions tagged `-GAI` |
| AVID — AI Vulnerability Database taxonomy | `avid` | S0100, S0200, S0301, S0400, S0500, P0201, P0204, P0301, E0101 |
| OWASP ML Security Top 10 | `owasp-ml` | ML01–ML10 |
| EU AI Act (Regulation 2024/1689) | `eu-ai-act` | Articles 10, 13, 14, 15, 50, 53, 55, 72 |
| ISO/IEC 42001 (AI Management System) | `iso-42001` | A.5.2, A.6.2.4/6, A.7.4, A.8.2/4, A.9.2, A.10.2/3 |
| Google Secure AI Framework (SAIF) | `google-saif` | SAIF-1 through SAIF-6 |

```bash
# List all standards
praxis scan standard --list

# Filter to a single standard
praxis scan standard owasp-llm .

# Filter to a single control within a standard
praxis scan standard owasp-llm . --control LLM01

# Programmatic JSON for tooling
praxis scan standard mitre-atlas . --json
```

In the JSON / SARIF / HTML reports:
- Each finding carries `standards: { 'owasp-llm': ['LLM01'], ... }`.
- The top-level `standardsSummary` shows per-standard coverage (e.g. `4/10`).
- SARIF embeds standards as `result.properties.standards` plus a flat `tags`
  array — GitHub Code Scanning will display them as labels.
- HTML reports render a "AI Security Standards Alignment" section.

**Adding a new standard**: drop a module under
`cli/utils/standards/sources/<name>.js` exporting `name`, `version`, `title`,
`description`, `url`, `controls`, and `mapFinding(finding)`; register it in
`ALL_STANDARDS` in `cli/utils/standards/index.js`. No other changes needed.

---

## Environment variables

### LLM providers (auto-detected by `--deep`, `fix`, `watch --stateful`)

| Variable | Purpose |
| --- | --- |
| `ANTHROPIC_API_KEY` | Claude (Opus / Sonnet / Haiku) |
| `OPENAI_API_KEY` | OpenAI (GPT-4 / GPT-4o / o1) |
| `GOOGLE_AI_API_KEY` | Gemini |
| `MOONSHOT_API_KEY` | Kimi |
| `OPENAI_BASE_URL` | Custom OpenAI-compatible endpoint (Groq, Together, LM Studio, etc.) |

`--local` uses Ollama; no key needed.

### Threat intelligence (raise rate limits)

| Variable | Purpose |
| --- | --- |
| `GITHUB_TOKEN` / `GH_TOKEN` | GHSA — raises GitHub rate limit |
| `NVD_API_KEY` | NVD — drops 6s wait between requests to 600ms |

### Optional paid intel sources

| Variable | Source |
| --- | --- |
| `SNYK_TOKEN` (+ `SNYK_ORG_ID`) | Snyk Vulnerability DB |
| `SOCKET_API_KEY` | Socket.dev supply-chain risk |
| `GITGUARDIAN_API_KEY` | GitGuardian secret detector definitions |
| `SONATYPE_USER` + `SONATYPE_TOKEN` | OSS Index (works anonymously too) |
| `PHYLUM_API_KEY` | Phylum supply-chain risk |

None are required. The six core intel sources and pattern-based scanning all
work with zero config.

### State location override (used by tests)

| Variable | Purpose |
| --- | --- |
| `HOME` (Unix) / `USERPROFILE` (Windows) | Relocates `~/.praxis/` |

---

## Configuration files

### `.praxisignore`

Per-line ignore patterns (gitignore-style) applied during file discovery.

```
# Skip vendored code
vendor/
third_party/
# Skip generated dirs
**/dist/**
```

### Inline suppression

Add `praxis-ignore` (optionally followed by a rule name) on the same line as
the finding:

```js
const fakeKey = "sk_test_dummy"; // praxis-ignore stripe-secret
```

### `.praxis.policy.json`

Project-level policy: severity floors, allowed CWEs, agent enable/disable,
suppression rules. Generate a template with:

```bash
praxis project policy init
```

### `.praxis/agents/*.js`

Custom agent plugins, auto-discovered when running scans from a project
that contains them. Scaffold one with:

```bash
praxis project plugins new my-rule
```

A plugin is any module exporting a class extending `BaseAgent`:

```js
import { BaseAgent, createFinding } from 'praxis';

export default class MyAgent extends BaseAgent {
  constructor() { super('MyAgent', 'description', 'category'); }
  async analyze(context) {
    const findings = [];
    // ...
    return findings;
  }
}
```

### `.praxis/baseline.json`

Snapshot of "known" findings. Created by `praxis project baseline .`. After
that, `--baseline` only surfaces new findings.

### `.praxis/history.json`

Trend tracking — last 100 score snapshots. Drives the `Trend` line in scan
output.

### `~/.praxis/threat-intel.json`

Merged threat-intel feed. Populated by `praxis intel update`. Falls back to
the bundled seed at `cli/data/threat-intel.json` when missing.

---

## Output formats

The output formatter registry lives in `cli/core/output/`. Built-in formats:

| Format | Flag | Notes |
| --- | --- | --- |
| `json` | `--json` | `schemaVersion: 3`, `findings[]`, `standardsSummary`, `compliance`, `agenticSummary` |
| `sarif` | `--sarif [file]` | SARIF 2.1.0; `result.properties.standards` + flat `tags` |
| `html` | `--html [file]` | Standalone interactive report with severity filter, search, standards alignment section |
| `pdf` | `--pdf [file]` | Print-rendered PDF (requires Chrome/Chromium) |
| `csv` | `--csv` | Tabular |
| `md` | `--md` | Markdown |

Add a new format by writing `cli/core/output/<name>.js` exporting
`default function(report, options): string` and registering it in `REGISTRY`
in `cli/core/output/index.js`.

---

## CI/CD integration

### GitHub Action (composite)

The repo ships an `action.yml` (composite action) that runs `praxis ci` and
uploads SARIF.

```yaml
- uses: ./
  with:
    path: .
    threshold: '80'
    deep: 'false'
    deps: 'true'
    sarif: 'true'
    comment: 'true'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Outputs: `score`, `grade`, `findings`, `secrets`, `vulns`, `cves`, `sarif-file`.

### Plain GitHub Actions

```yaml
- run: npm install -g praxis@latest
- run: praxis ci . --threshold 80 --sarif results.sarif --strict-intel
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

### Pre-commit hook

```bash
praxis project guard install --pre-commit
```

### Agentic loop (auto-fix until score target)

```bash
praxis fix . --severity high --branch praxis/fixes --pr
# review, then if needed:
praxis fix undo --all
```

---

## Custom plugins

Praxis discovers plugins from `.praxis/agents/` automatically when scans run
from that project root. The discovery uses `buildOrchestratorAsync(rootPath)` —
the synchronous `buildOrchestrator()` skips plugin loading.

A plugin extends `BaseAgent` and follows the standard contract:

```js
import { BaseAgent, createFinding } from 'praxis';

export default class HardcodedAdminCheck extends BaseAgent {
  constructor() {
    super(
      'HardcodedAdminCheck',
      'Detects hardcoded admin credentials',
      'auth'   // category — feeds into ScoringEngine
    );
  }

  shouldRun(recon) {
    return recon.languages?.has('javascript') || recon.languages?.has('typescript');
  }

  async analyze(context) {
    const files = this.getFilesToScan(context);
    const findings = [];
    for (const file of files) {
      // Use scanFileWithPatterns or your own logic
      findings.push(...this.scanFileWithPatterns(file, [
        {
          rule: 'hardcoded-admin',
          title: 'Hardcoded admin credential',
          regex: /admin\s*:\s*['"](password|admin)['"]/gi,
          severity: 'critical',
          cwe: 'CWE-798',
          owasp: 'A07:2021',
          description: 'Admin credential hardcoded in source.',
          fix: 'Move to environment variables.',
        },
      ]));
    }
    return findings;
  }
}
```

The standards registry will auto-tag these findings during scoring — no
plugin-side wiring required.

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `praxis intel update` is slow | NVD rate-limits to 6s/request without a key. Set `NVD_API_KEY`. |
| `praxis scan ci --strict-intel` fails locally | Run `praxis intel update` first. Default freshness window is `7d`. |
| Custom plugins not loading | Make sure you're running through `buildOrchestratorAsync(rootPath)` — the default `praxis scan` does this; programmatic API callers using `buildOrchestrator()` won't get plugins. |
| `node cli/bin/praxis.js` works but `praxis` doesn't | Run `npm link` once (or `npm install -g .` from the repo). |
| Test files report secrets | Confidence is auto-downgraded in test/doc/example paths — but use `praxis-ignore` for explicit suppression. |
| Feed lives somewhere else | Override `HOME` (Unix) or `USERPROFILE` (Windows) — used by the test suite. |
| Standards summary shows `0/X` everywhere | The standards registry maps via `cwe`/`owasp`/`category` on findings. If you've written a custom agent that doesn't set these, populate them in `createFinding({...})`. |

---

## Get help

```bash
praxis --help                    # all groups
praxis <group> --help            # subcommands for a group
praxis <group> <cmd> --help      # flags for a specific command
```

Report Praxis bugs or feature requests via the project's issue tracker on the
Praxis GitHub repository.
