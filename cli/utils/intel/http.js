/**
 * HTTP helper used by all intel source fetchers.
 *
 * - 30s timeout (overridable)
 * - Retries on 5xx and network errors with exponential backoff
 * - User-Agent header so providers can identify praxis traffic
 */

const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_RETRIES = 2;
const USER_AGENT = 'praxis-intel/1.0 (+https://github.com//praxis)';

export async function safeFetch(url, options = {}) {
  const { timeout = DEFAULT_TIMEOUT, retries = DEFAULT_RETRIES, ...rest } = options;

  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, {
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
