<h1 align="center">Praxis</h1>
<p align="center"><strong>From finding to fix, on autopilot.</strong></p>
<p align="center">AI-native security CLI for AI-augmented codebases. 25 parallel agents. Multi-source threat intel. Modular alignment with 8 AI-security standards. Agentic LLM-powered remediation loop.</p>

---

## What it is

Praxis is a single-binary security CLI that scans, fixes, and verifies. The
find→fix→verify loop is the product. A typical session:

1. **Find** — secrets, dependency CVEs, AI/MCP/skill threats, OWASP LLM Top 10,
   supply-chain risks, prompt-injection signatures, model-file deserialization
   risk.
2. **Plan** — an LLM (your choice of provider) drafts a fix with a unified diff.
3. **Ask** — accept, reject, or tweak each plan before anything is written.
4. **Apply** — Praxis writes atomically and logs the change.
5. **Verify** — re-scans the file to confirm the finding is gone.
6. **Undo** — every change is reversible from the log.

```
$ praxis
$ praxis scan .
$ praxis fix .
```

No signup. No mandatory API key. Works offline (LLM features are optional).

---

## Quick start

```bash
npm install
npm link                                 # exposes the `praxis` binary globally

praxis                                   # interactive REPL (TTY)
praxis scan .                            # full audit: secrets + 25 agents + deps + score
praxis fix .                             # interactive LLM-guided fixes
praxis intel update                      # refresh threat-intel feed
praxis vibe .                            # emoji-graded A–F score
```

Full reference: **[docs/USAGE.md](./docs/USAGE.md)**.

---

## The six command groups

```
praxis scan       run security scans (incl. scan standard <name> for AI-standard views)
praxis fix        apply remediations (LLM, deterministic, or PR-based)
praxis agents     audit AI/agent surface (skills, MCP, attestation, BOM)
praxis intel      threat-feed + advisory operations
praxis report     format/diff/share existing scan results
praxis project    init, hooks, watch, doctor, baseline, plugins, policies
```

Plus three top-level shortcuts: `praxis vibe`, `praxis score`, and `praxis`
alone (REPL on a TTY).

---

## 25 security agents

All agents run in parallel; each skips irrelevant projects automatically.

| Agent | Category | What it detects |
|---|---|---|
| **InjectionTester** | Code Vulns | SQL/NoSQL injection, command injection, XSS, path traversal, XXE, ReDoS, prototype pollution |
| **AuthBypassAgent** | Auth | JWT flaws (alg:none, weak secrets), CSRF, OAuth misconfig, BOLA/IDOR, TLS bypass |
| **SSRFProber** | SSRF | User input in fetch/axios, cloud metadata endpoints, internal IPs |
| **SupplyChainAudit** | Supply Chain | Typosquatting, wildcard versions, suspicious install scripts, dependency confusion |
| **ConfigAuditor** | Config | Docker (root user, :latest), Terraform, Kubernetes, CORS, CSP, Firebase, Nginx |
| **SupabaseRLSAgent** | Auth | service_role key in client code, tables without RLS, anon key inserts |
| **LLMRedTeam** | AI/LLM | OWASP LLM Top 10: prompt injection, excessive agency, system prompt leakage |
| **MCPSecurityAgent** | AI/LLM | MCP server misuse, tool poisoning, typosquatting, unvalidated inputs |
| **AgenticSecurityAgent** | AI/LLM | OWASP Agentic AI Top 10: agent hijacking, privilege escalation |
| **RAGSecurityAgent** | AI/LLM | Context injection, document poisoning, vector DB access control |
| **MemoryPoisoningAgent** | AI/LLM | Instruction injection in agent memory files, hidden Unicode payloads |
| **PIIComplianceAgent** | Compliance | SSNs, credit cards, emails, phone numbers in source code |
| **VibeCodingAgent** | Code Vulns | AI-generated code anti-patterns: no validation, empty catches, TODO-auth |
| **ExceptionHandlerAgent** | Code Vulns | Empty catches, unhandled rejections, leaked stack traces |
| **AgentConfigScanner** | AI/LLM | Prompt injection in `.cursorrules`, `CLAUDE.md`, malicious Claude Code hooks |
| **MobileScanner** | Mobile | OWASP Mobile Top 10: insecure storage, WebView injection, debug mode |
| **GitHistoryScanner** | Secrets | Leaked secrets in git commit history |
| **CICDScanner** | CI/CD | Pipeline poisoning, unpinned actions, secret logging |
| **APIFuzzer** | API | Routes without auth, mass assignment, GraphQL introspection, debug endpoints |
| **ManagedAgentScanner** | AI/LLM | Managed-agent misconfigs: always-allow policies, unrestricted networking |
| **HermesSecurityAgent** | AI/LLM | Tool registry poisoning, function-call injection, skill permission drift |
| **AgentAttestationAgent** | Supply Chain | Unpinned agent versions, missing integrity hashes, unsigned manifests |
| **AgenticSupplyChainAgent** | Supply Chain | Over-privileged AI CI actions, OAuth scope creep, unsigned AI webhook receivers |
| **ModelFileScanner** | AI/LLM | Pickle deserialization risk in `.pkl`/`.pt`/`.ckpt`, missing model card |
| **PromptInjectionProber** | AI/LLM | DAN-style prompts, persona bypass, indirect injection signatures |

**Post-processors:** ScoringEngine · VerifierAgent (secrets liveness) · DeepAnalyzer (LLM taint analysis)

---

## AI security standards alignment

Every finding is auto-tagged with all applicable standards. Eight modules ship
in `cli/utils/standards/sources/`:

`owasp-llm` · `mitre-atlas` · `nist-ai-600-1` · `avid` · `owasp-ml` ·
`eu-ai-act` · `iso-42001` · `google-saif`

```bash
praxis scan standard --list                        # list available standards
praxis scan standard owasp-llm .                   # filter to LLM Top 10 findings
praxis scan standard owasp-llm . --control LLM01   # one control
```

Reports include a per-standard coverage summary in JSON, SARIF (as
`result.properties.standards`), and HTML.

---

## Threat intelligence

Six free core sources and five optional paid sources, merged into a single
queryable feed at `~/.praxis/threat-intel.json`:

- **Core (free):** OSV.dev · GitHub Advisory DB · CISA KEV · EPSS · NVD · Gitleaks rules
- **Optional (paid):** Snyk · Socket.dev · GitGuardian · Sonatype OSS Index · Phylum

Findings are enriched with KEV (actively exploited) and EPSS (exploit-likelihood)
signals so you prioritize what matters first.

Architecture, env vars, TTLs, and how to add a custom source:
**[docs/THREAT_INTEL.md](./docs/THREAT_INTEL.md)**.

---

## CI integration

```bash
praxis scan ci . --threshold 80                    # fail build if score < 80
praxis scan ci . --sarif results.sarif             # SARIF for GitHub Code Scanning
praxis scan ci . --strict-intel --max-intel-age 7d # fail on stale threat intel
```

A composite GitHub Action ships in `action.yml`. See [docs/USAGE.md](./docs/USAGE.md#cicd-integration).

---

## Plugin system

Drop a `.js` file in `.praxis/agents/` exporting a default class extending
`BaseAgent`, and it'll load automatically on every audit.

```bash
praxis project plugins new my-rule
```

---

## Documentation

| Doc | Purpose |
| --- | --- |
| [docs/USAGE.md](./docs/USAGE.md) | Complete usage reference: every command, flag, environment variable, output format, and config file |
| [docs/THREAT_INTEL.md](./docs/THREAT_INTEL.md) | Threat-intel architecture, source list, custom-source authoring |
| [.github/CONTRIBUTING.md](./.github/CONTRIBUTING.md) | Setup, conventions, adding agents/standards/intel sources |
| [.github/SECURITY.md](./.github/SECURITY.md) | Vulnerability reporting policy |
| [.github/CODE_OF_CONDUCT.md](./.github/CODE_OF_CONDUCT.md) | Community guidelines |
| [CHANGELOG.md](./CHANGELOG.md) | Version history |

---

## License

MIT — see [LICENSE](./LICENSE).
