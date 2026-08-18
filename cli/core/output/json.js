/**
 * JSON output formatter.
 *
 * Reports are emitted with `schemaVersion` so consumers can pin to a
 * version. Bump the version when the shape changes in a breaking way.
 *
 * Scanner hardening: secret-category findings never expose their raw
 * matched value — `matched` is redacted centrally so no consumer of the
 * JSON report can leak a credential.
 */

const SCHEMA_VERSION = 3;

function redactFinding(f) {
  if (!f || typeof f !== 'object') return f;
  const isSecret = f.category === 'secrets' || f.category === 'secret'
    || /secret|api[_-]?key|token|password|credential/i.test(String(f.rule || ''));
  const out = { ...f };
  if (f.matched) {
    out.matched = isSecret
      ? `${String(f.matched).slice(0, 3)}***`
      : String(f.matched).slice(0, 160);
  }
  if (out.file) {
    out.file = String(out.file)
      .replace(/\\/g, '/')
      .replace(/^[a-zA-Z]:\/+/, '')
      .replace(/^.*\/Praxis\/showcase-target\//, 'showcase-target/')
      .replace(/^.*\/Praxis\//, '');
  }
  return out;
}

export default function json(report, options = {}) {
  const { pretty = true } = options;
  const enriched = {
    schemaVersion: SCHEMA_VERSION,
    ...report,
  };
  if (Array.isArray(enriched.findings)) {
    enriched.findings = enriched.findings.map(redactFinding);
  }
  return pretty
    ? JSON.stringify(enriched, null, 2)
    : JSON.stringify(enriched);
}

export { redactFinding, SCHEMA_VERSION };
