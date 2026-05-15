/**
 * Output formatter registry
 * =========================
 *
 * Centralized place to register output formats so `--format <name>` is a
 * lookup, not a per-command switch statement. Eliminates the 4 separate
 * formatter implementations that previously lived inline in
 * `cli/commands/{audit,ci,team-report,diff}.js`.
 *
 * Usage:
 *   import { render } from 'cli/core/output/index.js';
 *   const text = render('json', report);
 *   console.log(text);
 *
 * Adding a new format: write a renderer at `./your-format.js` that
 * exports `default function(report, options): string`, then add it to
 * the registry below.
 */

import json from './json.js';
import sarif from './sarif.js';

const REGISTRY = {
  json,
  sarif,
};

export function listFormats() {
  return Object.keys(REGISTRY);
}

export function hasFormat(name) {
  return Object.prototype.hasOwnProperty.call(REGISTRY, name);
}

/**
 * Render `report` into the requested format. Throws if the format is
 * unknown so callers can present the available list.
 */
export function render(format, report, options = {}) {
  const renderer = REGISTRY[format];
  if (!renderer) {
    throw new Error(
      `unknown format '${format}'. available: ${listFormats().join(', ')}`
    );
  }
  return renderer(report, options);
}

/**
 * Register an additional format at runtime. Used by tests and plugins.
 */
export function registerFormat(name, renderer) {
  REGISTRY[name] = renderer;
}
