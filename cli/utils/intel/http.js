/**
 * HTTP helper used by all intel source fetchers.
 *
 * - 30s timeout (overridable)
 * - Retries on 5xx and network errors with exponential backoff
 * - User-Agent header so providers can identify praxis traffic
 */

const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_RETRIES = 2;
const USER_AGENT = 'praxis-intel/1.0 (+https://github.com/Ganron007/Praxis)';

export async function safeFetch(url, options = {}) {
  const { timeout = DEFAULT_TIMEOUT, retries = DEFAULT_RETRIES, ...rest } = options;

  // Scanner hardening: only allow http/https to external feed endpoints.
  // Prevents SSRF if a future intel source ever resolves a fetch target from
  // untrusted data (file://, ftp://, and internal hosts are rejected).
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`safeFetch: invalid URL ${String(url).slice(0, 80)}`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`safeFetch: non-http(s) scheme rejected: ${parsed.protocol}`);
  }
  const LOOPBACK_RE = /^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1|localhost)(?:[:/]|$)/i;
  if (LOOPBACK_RE.test(parsed.hostname)) {
    throw new Error(`safeFetch: loopback/private host rejected: ${parsed.hostname}`);
  }

  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { // praxis-ignore SSRF_USER_URL_FETCH — scheme + loopback guarded above
        ...rest,
        signal: controller.signal,
        headers: {
          'User-Agent': USER_AGENT,
          ...(rest.headers || {}),
        },
      });
      clearTimeout(timer);

      // Retry on 5xx, otherwise return whatever we got (caller decides)
      if (res.status >= 500 && attempt < retries) {
        await sleep(backoffMs(attempt));
        continue;
      }
      return res;
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
      if (attempt < retries) {
        await sleep(backoffMs(attempt));
        continue;
      }
    }
  }
  throw lastErr || new Error(`Failed to fetch ${url}`);
}

export async function fetchJson(url, options = {}) {
  const res = await safeFetch(url, options);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}`);
  }
  return res.json();
}

export async function fetchText(url, options = {}) {
  const res = await safeFetch(url, options);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}`);
  }
  return res.text();
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function backoffMs(attempt) {
  return Math.min(1000 * Math.pow(2, attempt), 8000);
}
