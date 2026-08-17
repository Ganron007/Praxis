# Praxis Plugin for Claude Code

Security audit your projects directly inside Claude Code. 28 agents, 80+ attack classes, zero setup.

## Install

```bash
claude plugin add github:Ganron007/Praxis
```

## Skills

| Command | Description |
|---------|-------------|
| `/praxis` | Full security audit — 28 agents, 80+ attack classes, prioritized remediation plan |
| `/praxis-hooks` | Install real-time hooks — block secrets & dangerous commands on every Write/Bash |
| `/praxis-scan` | Quick scan for leaked secrets (API keys, passwords, tokens) |
| `/praxis-score` | Security health score (0-100, A-F grade) |
| `/praxis-red-team` | Multi-agent red team scan — deep vulnerability analysis |
| `/praxis-baseline` | Manage security baseline — only report new regressions |
| `/praxis-fix` | Auto-fix security issues (secrets, TLS, debug mode, XSS, Docker) |
| `/praxis-deep` | LLM-powered deep taint analysis for critical/high findings |
| `/praxis-ci` | CI/CD pipeline setup — GitHub Actions, GitLab CI examples |

## How It Works

These skills invoke [praxis](https://www.npmjs.com/package/praxis) via `npx`, so you always get the latest version. No API keys required — Claude Code itself interprets the results, explains findings in plain language, and can directly fix issues in your codebase.

## Examples

```
> /praxis-hooks
Installs praxis as PreToolUse + PostToolUse hooks in ~/.claude/settings.json.
After this, every Write/Edit call is scanned for secrets before it hits disk,
and every Bash call is checked for dangerous patterns like curl|bash.

> /praxis
Runs full audit with all 28 security agents, shows score, findings grouped
by severity, and offers to fix critical issues in your code.

> /praxis-scan src/
Scans src/ directory for leaked secrets and offers to move them to
environment variables.

> /praxis-score
Quick score check — tells you if your project is safe to ship.

> /praxis-red-team . --agents injection,auth
Deep dive into injection and auth vulnerabilities with specialized agents.

> /praxis-baseline .
Accept current findings as baseline. Future scans only show new regressions.

> /praxis-fix . --all
Auto-fix hardcoded secrets AND common vulnerabilities (TLS bypass, debug
mode, XSS, Docker :latest, shell injection).
```

## What Gets Scanned

- Secrets (API keys, passwords, tokens, database URLs)
- Injection vulnerabilities (SQL, NoSQL, XSS, command injection)
- Auth bypass (JWT, CSRF, OAuth, IDOR)
- SSRF (user input in HTTP clients, cloud metadata)
- Supply chain (typosquatting, dependency confusion, wildcard versions)
- Supabase RLS (missing Row Level Security, service_role key exposure)
- Config (Docker, Terraform, Kubernetes, CORS, CSP)
- LLM security (prompt injection, system prompt leakage)
- MCP server security (tool poisoning, missing auth)
- Agentic AI (OWASP Agentic AI Top 10 — agent hijacking, privilege escalation)
- RAG pipelines (context injection, document poisoning)
- PII compliance (SSNs, credit cards, emails in source code)
- CI/CD (pipeline poisoning, unpinned actions)
- API (missing auth, rate limiting, OpenAPI spec issues)
- Dependencies (known CVEs in npm, pip, bundler)

## Requirements

- Node.js 18+
- Claude Code CLI

## Links

- [Praxis on npm](https://www.npmjs.com/package/praxis)
- [Praxis usage reference](../docs/USAGE.md)
