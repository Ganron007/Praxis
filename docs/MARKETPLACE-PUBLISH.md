# Publishing Praxis to the GitHub Marketplace

Everything on our side is done. This is the remaining work, which is account-side by
design — only the repo owner can publish.

**State as of the last commit:**

| Check | Status |
|---|---|
| `action.yml` exists, valid YAML, composite action | ✅ |
| `name`, `description`, `author` present | ✅ |
| `branding.icon` + `branding.color` set | ✅ |
| Actions pinned to v7 (Node 24 runtime) — no deprecation warning | ✅ |
| Inputs / outputs documented | ✅ 12 inputs, 8 outputs |
| SARIF upload with `security-severity` (real ranking in Code Scanning) | ✅ |
| Anti-CSRF / net-new gate / fail-on thresholds | ✅ |
| README badge + usage docs | ✅ |
| CI green on Node 18/20/22/24 | ✅ |
| npm package published (`npx praxis`) | ✅ (separate registry — already live) |

---

## Step 1 — Create the listing

1. Open the repo: <https://github.com/Ganron007/Praxis>
2. You should see the banner **"You can publish this Action to the GitHub Marketplace"**.
   If it has gone, use **Settings → Actions → General → Marketplace** → *Publish* action.
3. GitHub opens a draft listing pre-filled from `action.yml`. Review:

   - **Categories** — tick *Security*, *Code testing*, *Static analysis*, *CI/CD*.
   - **Description** — a short paragraph in your own words. Suggested copy:

     > AI-native security scanning built for AI-era codebases. Where most scanners look for
     > SQL injection and leaked keys, Praxis assesses the attack surface those tools miss:
     > LLM applications, agent configs, MCP servers, RAG pipelines, model files, datasets and
     > eval harnesses — 28 agents in parallel, mapped to 8 security frameworks. Findings upload
     > to Code Scanning as SARIF with real severity ranking, and a net-new gate fails only on
     > problems your PR actually introduced, so an inherited backlog never blocks a merge.
     > Complements classic SAST rather than replacing it. Runs offline; LLM remediation is opt-in.

   - **Icon / color** — already set (`shield`, `blue`).
4. Click **Publish**.

That creates the listing. It is not yet usable via `uses:`, because the Marketplace resolves
by release tag.

---

## Step 2 — Publish a release (this is what makes `uses:` work)

The Marketplace pins the action to a version tag. In the repo:

```bash
git tag v1        # marketplace major version
git push origin v1
```

Or via the UI: **Releases → Draft a new release → tag `v1` → publish**. Either is fine;
the tag is what matters.

After this, anyone can use:

```yaml
- uses: Ganron007/Praxis@v1
```

> **Use `@v1`, not `@master`, in published examples.** A moving ref in a Marketplace
> listing is bad practice and GitHub warns about it. The README currently shows `@master`
> because that worked pre-Marketplace; switch it to `@v1` after step 2.

---

## Step 3 — Verify

1. Browse the listing: <https://github.com/marketplace/actions/praxis-security-scan>
2. Create a throwaway repo with this workflow and confirm it runs:

```yaml
name: praxis
on: [push, pull_request]
permissions:
  security-events: write      # required for sarif: true
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: Ganron007/Praxis@v1
        with:
          sarif: 'true'
          net-new: 'true'
          fail-on-new: 'high'
```

3. Open the repo's **Security → Code scanning** tab. Findings should appear with **distinct
   severities** (critical vs high should no longer look identical — that is the
   `security-severity` property working).
4. Open a PR on the throwaway repo and confirm the net-new gate only complains about
   findings the PR introduced.

---

## Step 4 — After publishing, one small follow-up

Change the README usage snippet from `@master` to `@v1`:

```bash
sed -i 's|Ganron007/Praxis@master|Ganron007/Praxis@v1|' README.md
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| No publish banner | Only the repo owner can publish. Check you are signed in as `Ganron007`. |
| Listing exists but `uses: @v1` fails | No release tag yet — complete step 2. The Marketplace resolves by tag, not by branch. |
| SARIF upload fails with 403 | The workflow needs `permissions: security-events: write`. |
| Findings all look the same severity | Confirm `security-severity` is in the SARIF: `jq '.runs[0].tool.driver.rules[0].properties' report.sarif`. |
| Deprecation warning about Node 20 | Fixed — actions are pinned to v7. Re-pull if you pinned v4 locally. |

---

## Notes

- **The npm package and the Marketplace listing are independent.** `npm publish` ships the
  CLI; the Marketplace ships the CI action. Publishing one does nothing for the other.
- **The action installs the CLI from npm** (`npm install -g praxis@latest`), so the CLI and
  the action can version independently.
- **Version skew is possible**: `uses: @v1` could pull a newer CLI than you tested if a new
  npm version ships without a Marketplace bump. That is usually what you want; if you need
  strict pinning, the action respects `PRAXIS_VERSION` in a future release — not implemented yet.