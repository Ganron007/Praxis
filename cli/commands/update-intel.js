/**
 * Update Intel Command
 * =====================
 *
 * Refreshes the local threat-intelligence database by fetching every
 * configured source in parallel (OSV, GHSA, KEV, EPSS, NVD, Gitleaks,
 * plus optional paid sources Snyk / Socket / GitGuardian / Sonatype /
 * Phylum). Results are merged into ~/.praxis/threat-intel.json.
 *
 * USAGE:
 *   praxis intel update                  Refresh all sources
 *   praxis intel update --only osv,kev   Limit to listed sources
 *   praxis intel update --force          Ignore per-source TTL caches
 *   praxis intel update --list           Print available sources
 */

import chalk from 'chalk';
import * as output from '../utils/output.js';
import { ThreatIntel } from '../utils/threat-intel.js';
import * as intel from '../utils/intel/index.js';

export async function updateIntelCommand(options = {}) {
  console.log();
  output.header('Praxis — Threat Intelligence Update');
  console.log();

  if (options.list) {
    printSources();
    return;
  }

  const before = ThreatIntel.stats();
  console.log(chalk.gray(`  Current version: ${before.version}`));
  console.log(chalk.gray(`  Last updated:    ${before.updated || 'never'}`));
  console.log();

  const sourceFilter = options.only
    ? String(options.only).split(',').map(s => s.trim()).filter(Boolean)
    : null;

  console.log(chalk.cyan('  Fetching sources...'));
  console.log();

  const result = await intel.runUpdate({
    sources: sourceFilter,
    force: !!options.force,
    onProgress: ({ source, status, message }) => {
      const pad = source.padEnd(12);
      switch (status) {
        case 'start':
          // Skip per-source 'start' lines — the per-source result line below
          // is enough output, and 'start' interleaving with 'ok' from parallel
          // fetches looks messy on a non-TTY.
          break;
        case 'ok':
          console.log(chalk.green(`    ${pad}  OK`));
          break;
        case 'cached':
          console.log(chalk.gray(`    ${pad}  cached`));
          break;
        case 'skipped':
          console.log(chalk.yellow(`    ${pad}  skipped`) + chalk.gray(` (${message || 'no key'})`));
          break;
        case 'error':
          console.log(chalk.red(`    ${pad}  error`) + chalk.gray(` (${message})`));
          break;
      }
    },
  });

  // Invalidate the in-memory ThreatIntel cache so the stats below reflect
  // the freshly merged feed.
  ThreatIntel._resetCache();

  console.log();
  console.log(chalk.green.bold(`  Merged feed v${result.merged.version} written.`));
  console.log();

  // Per-source summary
  const rows = Object.entries(result.merged.sources || {});
  if (rows.length) {
    console.log(chalk.gray('  Per-source status:'));
    for (const [name, info] of rows) {
      const flag = info.skipped
        ? chalk.yellow('skipped')
        : info.ok ? chalk.green('ok') : chalk.red('failed');
      const stats = info.stats ? Object.entries(info.stats).map(([k, v]) => `${v} ${k}`).join(', ') : '';
      const note = info.skipped ? ` (${info.reason || 'no key'})` : info.error ? ` (${info.error})` : '';
      console.log(`    ${name.padEnd(12)} ${flag.padEnd(18)} ${chalk.gray(stats + note)}`);
    }
    console.log();
  }

  // Aggregate stats
  const after = ThreatIntel.stats();
  console.log(chalk.gray('  Indicators loaded:'));
  console.log(`    CVE advisories:   ${after.cveAdvisories}`);
  console.log(`    KEV entries:      ${after.kevEntries}`);
  console.log(`    EPSS scores:      ${after.epssScores}`);
  console.log(`    NVD details:      ${after.nvdDetails}`);
  console.log(`    Extra secret rules: ${after.extraSecretRules}`);
  console.log(`    Malicious skills: ${after.hashes}`);
  console.log(`    Compromised MCP:  ${after.servers}`);
  console.log();
}

function printSources() {
  const sources = intel.listSources();
  console.log(chalk.gray('  Available sources:'));
  console.log();
  const core = sources.filter(s => s.tier === 'core');
  const optional = sources.filter(s => s.tier === 'optional');

  console.log(chalk.cyan('  Core (free, no auth required):'));
  for (const s of core) {
    console.log(`    ${chalk.bold(s.name.padEnd(12))} ${chalk.gray(s.description)}`);
  }
  console.log();
  console.log(chalk.cyan('  Optional (paid; activate by setting env var):'));
  for (const s of optional) {
    const flag = process.env[s.envKey] ? chalk.green('[active]') : chalk.gray('[inactive]');
    console.log(`    ${chalk.bold(s.name.padEnd(12))} ${flag} ${chalk.gray(`needs ${s.envKey}`)}`);
    console.log(`    ${''.padEnd(12)} ${chalk.gray(s.description)}`);
  }
  console.log();
}
