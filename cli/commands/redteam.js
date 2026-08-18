/**
 * Praxis Red Team CLI Command (Dynamic AI DAST & Endpoint Prober)
 * ===============================================================
 *
 * Actively probes live AI/LLM endpoints for prompt injection, jailbreaks,
 * and tool hijacking.
 *
 * USAGE:
 *   praxis redteam https://api.example.com/v1/chat
 *   praxis redteam http://localhost:8000/predict --header "Authorization: Bearer token"
 *   praxis redteam http://localhost:3000/api/agent --json
 */

import chalk from 'chalk';
import ora from 'ora';
import { LLMRedTeamEngine } from '../agents/llm-redteam.js';
import * as output from '../utils/output.js';
import { printBanner } from '../core/branding.js';

export async function redteamCommand(endpoint, options = {}) {
  if (!endpoint) {
    output.error('Target endpoint URL is required: praxis redteam <url>');
    process.exit(1);
  }

  if (!options.json) {
    printBanner();
    output.header(`Dynamic AI Red Team: ${endpoint}`);
    console.log();
  }

  const spinner = options.json ? null : ora({ text: 'Executing dynamic behavioral probes...', color: 'cyan' }).start();

  try {
    const headers = {};
    if (options.header) {
      const parts = Array.isArray(options.header) ? options.header : [options.header];
      for (const h of parts) {
        const [k, ...v] = h.split(':');
        if (k && v.length) headers[k.trim()] = v.join(':').trim();
      }
    }

    const report = await LLMRedTeamEngine.probeEndpoint(endpoint, {
      headers,
      timeoutMs: options.timeout ? parseInt(options.timeout, 10) : 10000,
    });

    if (spinner) spinner.succeed(chalk.green('Probing complete'));

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
      return report;
    }

    console.log();
    console.log(chalk.bold(`  Endpoint Security Score: ${report.securityScore}/100`));
    console.log(chalk.gray(`  Probes executed: ${report.totalProbes} | Passed: ${report.passedCount} | Failed: ${report.failedCount}`));
    console.log();

    for (const res of report.probeResults) {
      const statusIcon = res.isVulnerable ? chalk.red('✖ FAILED (Vulnerable)') : chalk.green('✔ PASSED (Refused/Protected)');
      console.log(`  ${statusIcon}  ${chalk.bold(res.name)} ${chalk.gray(`[${res.severity}]`)}`);
      if (res.isVulnerable && res.responseSnippet) {
        console.log(chalk.red(`     Response snippet: "${res.responseSnippet}..."`));
      }
    }
    console.log();

    return report;
  } catch (err) {
    if (spinner) spinner.fail(chalk.red(`Red team probing failed: ${err.message}`));
    else output.error(`Red team probing failed: ${err.message}`);
    process.exit(1);
  }
}

export default redteamCommand;
