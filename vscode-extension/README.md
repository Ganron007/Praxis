# Praxis — VS Code Extension

Real-time AI-security scanning inside VS Code. Scans your workspace (and each
saved file) with the Praxis CLI — 28 security agents covering secrets,
vulnerabilities, and the AI/agent attack surface — and surfaces findings as
editor diagnostics.

## Features

- **Scan Workspace** (`Praxis: Scan Workspace`) — full 28-agent audit
- **Scan Current File** (`Praxis: Scan Current File`) — quick file check
- **Show Report** (`Praxis: Show Report`) — open the scan report
- **Toggle Watch Mode** (`Praxis: Toggle Watch Mode`) — continuous monitoring
- **Auto-scan on save** — diagnostics appear inline as you type (configurable)

## Requirements

- Node.js ≥ 18
- The `praxis` CLI — installed globally (`npm install -g praxis`) or configured
  via the `praxis.cliPath` setting

## Configuration

| Setting | Default | Description |
|---|---|---|
| `praxis.autoScanOnSave` | `true` | Scan files automatically on save |
| `praxis.severity` | `medium` | Minimum severity shown in diagnostics |
| `praxis.showInlineHints` | `true` | Show inline hints for findings |
| `praxis.deep` | `false` | Enable AI deep analysis (requires API key) |
| `praxis.cliPath` | `""` | Path to the praxis executable; empty = `npx praxis` |

## Build

```bash
npm install
npm run compile     # tsc
npm run package     # vsce package
```

## License

MIT — see the repository LICENSE. See also
[docs/THIRD_PARTY_NOTICES.md](../docs/THIRD_PARTY_NOTICES.md) for vendored data
attribution.
