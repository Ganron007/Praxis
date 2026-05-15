/**
 * JSON output formatter.
 *
 * Reports are emitted with `schemaVersion` so consumers can pin to a
 * version. Bump the version when the shape changes in a breaking way.
 */

const SCHEMA_VERSION = 3;

export default function json(report, options = {}) {
  const { pretty = true } = options;
  const enriched = {
    schemaVersion: SCHEMA_VERSION,
    ...report,
  };
  return pretty
    ? JSON.stringify(enriched, null, 2)
    : JSON.stringify(enriched);
}
