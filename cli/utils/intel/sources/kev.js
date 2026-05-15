/**
 * CISA KEV — Known Exploited Vulnerabilities catalog.
 * https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 *
 * Single JSON, refreshed daily. ~1300 entries. We keep just the CVE IDs
 * + minimal metadata; downstream code uses isInKev(cve) for prioritization.
 */

import { fetchJson } from '../http.js';

const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TTL_MS = 24 * 60 * 60 * 1000; // 24h

export const name = 'kev';
export const tier = 'core';
export const description = 'CISA Known Exploited Vulnerabilities catalog';

export async function fetchAll() {
  const data = await fetchJson(URL);
  const entries = (data.vulnerabilities || []).map(v => ({
    cve: v.cveID,
    vendor: v.vendorProject,
    product: v.product,
    name: v.vulnerabilityName,
    dateAdded: v.dateAdded,
    dueDate: v.dueDate,
    requiredAction: v.requiredAction,
    knownRansomware: v.knownRansomwareCampaignUse === 'Known',
  }));

  return {
    catalogVersion: data.catalogVersion,
    dateReleased: data.dateReleased,
    entries,
  };
}

export const TTL = TTL_MS;
