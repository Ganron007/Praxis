/**
 * Praxis Threat-Pack — AI attack-vector signature pack (core feed)
 * ===============================================================
 *
 * A versioned, fetchable pack of AI-security detection knowledge:
 *   - probes:    prompt-injection signatures (same schema as the bundled
 *                corpus — new jailbreak/obfuscation families arrive as data)
 *   - eaa:       Endpoint-AI-Agent-Abuse technique additions
 *   - gateways:  known model-gateway domains (allowlist updates)
 *
 * The bundled seed lives at cli/data/threatpacks/latest.json. The feed
 * URL can be overridden with PRAXIS_THREATPACK_URL (defaults to the seed
 * version on GitHub). Graceful degradation: a fetch failure marks the
 * source failed and the scan continues with the bundled corpus.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { fetchText } from '../http.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SEED_PATH = path.join(__dirname, '..', '..', '..', 'data', 'threatpacks', 'latest.json');

const DEFAULT_URL = 'https://raw.githubusercontent.com/Ganron007/Praxis/main/cli/data/threatpacks/latest.json';
const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7d

export const name = 'threatpack';
export const tier = 'core';
export const description = 'Praxis AI attack-vector signature pack (probes, EAA additions, gateway allowlists)';

function loadSeed() {
  try {
    return JSON.parse(fs.readFileSync(SEED_PATH, 'utf-8'));
  } catch {
    return { version: '0.0.0', probes: [], eaa: [], gateways: [] };
  }
}

export async function fetchAll() {
  const seed = loadSeed();
  const url = process.env.PRAXIS_THREATPACK_URL || DEFAULT_URL;

  // Try the remote pack; fall back to the bundled seed on any failure.
  try {
    const raw = await fetchText(url);
    const pack = JSON.parse(raw);
    if (!pack.version || !Array.isArray(pack.probes)) {
      throw new Error('malformed threat pack');
    }
    return {
      sourceUrl: url,
      version: pack.version,
      probes: pack.probes,
      eaa: pack.eaa || [],
      gateways: pack.gateways || [],
      fetchedRemote: true,
    };
  } catch {
    return {
      sourceUrl: SEED_PATH,
      version: seed.version,
      probes: seed.probes || [],
      eaa: seed.eaa || [],
      gateways: seed.gateways || [],
      fetchedRemote: false,
    };
  }
}
