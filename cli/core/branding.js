/**
 * Praxis branding & identity
 * ==========================
 *
 * Single source of truth for the banner, tagline, and product name used
 * across the CLI. Importing this avoids hardcoded "praxis" / "Praxis"
 * strings drifting out of sync after the rebrand.
 */

import chalk from 'chalk';

export const PRODUCT_NAME = 'praxis';
export const PRODUCT_DISPLAY = 'Praxis';
export const TAGLINE = 'From finding to fix, on autopilot.';
export const SUBTITLE = '27 agents. AI-native security with agentic remediation.';

/**
 * Print the praxis ASCII banner. Call at the top of any command that
 * should show branding (mostly `--help` and `praxis` with no args).
 */
export function printBanner(version) {
  console.log();
  console.log(chalk.cyan('██████╗ ██████╗  █████╗ ██╗  ██╗██╗███████╗'));
  console.log(chalk.cyan('██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝██║██╔════╝'));
  console.log(chalk.cyan('██████╔╝██████╔╝███████║ ╚███╔╝ ██║███████╗'));
  console.log(chalk.cyan('██╔═══╝ ██╔══██╗██╔══██║ ██╔██╗ ██║╚════██║'));
  console.log(chalk.cyan('██║     ██║  ██║██║  ██║██╔╝ ██╗██║███████║'));
  console.log(chalk.cyan('╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝'));
  console.log();
  console.log(chalk.white.bold(`  ${TAGLINE}`));
  if (version) {
    console.log(chalk.gray(`  v${version} · ${SUBTITLE}`));
  } else {
    console.log(chalk.gray(`  ${SUBTITLE}`));
  }
  console.log();
}
