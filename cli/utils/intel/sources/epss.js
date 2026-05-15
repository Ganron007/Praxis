/**
 * EPSS — Exploit Prediction Scoring System (FIRST.org).
 * https://www.first.org/epss/
 *
 * Daily CSV. We download the gzipped current scores and parse into a map
 * keyed by CVE → { score, percentile }. ~250k CVEs, ~10MB compressed.
 *
 * Score is 0..1, the probability the CVE will be exploited in the wild
 * within 30 days. Used to sort findings by real-world risk.
 */

import zlib from 'zlib';
import { promisify } from 'util';
import { safeFetch } from '../http.js';

const URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
const TTL_MS = 24 * 60 * 60 * 1000; // 24h
const gunzip = promisify(zlib.gunzip);

export const name = 'epss';
export const tier = 'core';
export const description = 'EPSS — exploit-likelihood scores from FIRST.org';

export async function fetchAll() {
  const res = await safeFetch(URL);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const buf = Buffer.from(await res.arrayBuffer());
  const csv = (await gunzip(buf)).toString('utf-8');

  const scores = {};
  const lines = csv.split('\n');
  let modelDate = null;

  for (const line of lines) {
    if (!line || line.startsWith('#')) {
      // Header lines look like: #model_version:v2025.03.14
      const m = line.match(/score_date:([0-9-]+)/);
      if (m) modelDate = m[1];
      continue;
    }
    if (line.startsWith('cve,')) continue; // column header
    const [cve, score, percentile] = line.split(',');
    if (!cve || !score) continue;
    scores[cve] = {
      score: parseFloat(score),
      percentile: parseFloat(percentile),
    };
  }

  return { modelDate, count: Object.keys(scores).length, scores };
}

export const TTL = TTL_MS;
