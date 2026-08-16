/**
 * Merge per-source payloads into the unified threat-intel.json schema
 * consumed by ThreatIntel and the agents.
 *
 * Schema additions on top of the existing seed:
 *   - cveAdvisories[]   from OSV + GHSA + NVD
 *   - kevList[]         from CISA KEV
 *   - epssScores{}      cve → { score, percentile }
 *   - osvIndex{}        ecosystem/package → [advisory]
 *   - ghsaIndex{}       ecosystem/package → [advisory]
 *   - secretRules[]     extra patterns from Gitleaks (+ optional GitGuardian)
 *   - sources{}         per-source health: { fetchedAt, count, error?, skipped? }
 */

export function mergeIntel(seedData, results) {
  // results: array of { name, ok, payload, error, skipped, fetchedAt }
  const merged = JSON.parse(JSON.stringify(seedData || {}));
  merged.version = bumpVersion(merged.version || '1.0.0');
  merged.updated = new Date().toISOString();
  merged.sources = merged.sources || {};

  // Reset only the collections owned by sources being freshly merged, so a
  // subset update (--only) preserves data from the other sources.
  const fresh = new Set(results.filter(r => r.ok && !r.skipped).map(r => r.name));
  if (fresh.has('kev')) { merged.kevList = []; merged.kevDetails = {}; }
  if (fresh.has('epss')) { merged.epssScores = {}; }
  if (fresh.has('nvd')) { merged.nvdDetails = {}; }
  if (fresh.has('osv')) merged.osvIndex = {};
  if (fresh.has('ghsa')) merged.ghsaIndex = {};
  if (fresh.has('gitleaks') || fresh.has('gitguardian')) merged.secretRules = [];

  // Drop stale advisories from sources being refreshed; keep the rest and
  // rebuild the dedup index from the survivors.
  merged.cveAdvisories = (merged.cveAdvisories || []).filter(a => !fresh.has(a.source));
  merged._cveAdvisorySeen = new Set(merged.cveAdvisories.map(a => `${a.cve}@${a.source}`));

  for (const r of results) {
    merged.sources[r.name] = {
      ok: r.ok,
      fetchedAt: r.fetchedAt || null,
      skipped: r.skipped || false,
      reason: r.skipped ? r.payload?.reason : undefined,
      error: r.ok ? null : (r.error || null),
      stats: r.ok && !r.skipped ? sourceStats(r) : null,
    };

    if (!r.ok || r.skipped) continue;

    switch (r.name) {
      case 'osv': mergeOsv(merged, r.payload); break;
      case 'ghsa': mergeGhsa(merged, r.payload); break;
      case 'kev': mergeKev(merged, r.payload); break;
      case 'epss': mergeEpss(merged, r.payload); break;
      case 'nvd': mergeNvd(merged, r.payload); break;
      case 'gitleaks': mergeGitleaks(merged, r.payload); break;
      case 'snyk': mergeSnyk(merged, r.payload); break;
      case 'socket': mergeSocket(merged, r.payload); break;
      case 'gitguardian': mergeGitguardian(merged, r.payload); break;
      case 'sonatype': mergeSonatype(merged, r.payload); break;
      case 'phylum': mergePhylum(merged, r.payload); break;
    }
  }

  return merged;
}

function bumpVersion(v) {
  const parts = String(v).split('.').map(Number);
  while (parts.length < 3) parts.push(0);
  parts[2] = parts[2] + 1;
  return parts.join('.');
}

function sourceStats(r) {
  const p = r.payload || {};
  if (Array.isArray(p.records)) return { records: p.records.length };
  if (Array.isArray(p.entries)) return { entries: p.entries.length };
  if (Array.isArray(p.advisories)) return { advisories: p.advisories.length };
  if (Array.isArray(p.detectors)) return { detectors: p.detectors.length };
  if (Array.isArray(p.rules)) return { rules: p.rules.length };
  if (Array.isArray(p.issues)) return { issues: p.issues.length };
  if (typeof p.count === 'number') return { count: p.count };
  if (p.scores) return { scores: Object.keys(p.scores).length };
  if (p.details) return { details: Object.keys(p.details).length };
  return {};
}

function mergeOsv(merged, payload) {
  for (const r of payload.records || []) {
    const key = `${r.ecosystem}/${r.package}`;
    (merged.osvIndex[key] = merged.osvIndex[key] || []).push(r);
    for (const cve of r.cves || []) {
      addCveAdvisory(merged, {
        cve, source: 'osv', summary: r.summary, severity: r.severity,
        package: r.package, ecosystem: r.ecosystem, references: r.references,
      });
    }
  }
}

function mergeGhsa(merged, payload) {
  for (const adv of payload.advisories || []) {
    for (const v of adv.vulnerabilities || []) {
      if (!v.package) continue;
      const key = `${v.ecosystem}/${v.package}`;
      (merged.ghsaIndex[key] = merged.ghsaIndex[key] || []).push({
        ghsaId: adv.ghsaId, cveId: adv.cveId,
        severity: adv.severity, summary: adv.summary,
        vulnerable_version_range: v.vulnerable_version_range,
        first_patched_version: v.first_patched_version,
      });
    }
    if (adv.cveId) {
      addCveAdvisory(merged, {
        cve: adv.cveId, source: 'ghsa', summary: adv.summary,
        severity: adv.severity, references: adv.references, ghsaId: adv.ghsaId,
      });
    }
  }
}

function mergeKev(merged, payload) {
  merged.kevList = (payload.entries || []).map(e => e.cve);
  merged.kevDetails = Object.fromEntries((payload.entries || []).map(e => [e.cve, e]));
  merged.kevCatalogVersion = payload.catalogVersion;
}

function mergeEpss(merged, payload) {
  merged.epssScores = payload.scores || {};
  merged.epssModelDate = payload.modelDate;
}

function mergeNvd(merged, payload) {
  merged.nvdDetails = payload.details || {};
}

function mergeGitleaks(merged, payload) {
  for (const r of payload.rules || []) {
    merged.secretRules.push({
      id: r.id,
      description: r.description,
      regex: r.regex,
      source: 'gitleaks',
      severity: 'high',
    });
  }
}

function mergeSnyk(merged, payload) {
  for (const issue of payload.issues || []) {
    for (const cve of issue.cves || []) {
      addCveAdvisory(merged, {
        cve, source: 'snyk', summary: issue.title,
        severity: issue.severity,
      });
    }
  }
}

function mergeSocket(merged, payload) {
  merged.socketAdvisories = payload.advisories || [];
}

function mergeGitguardian(merged, payload) {
  for (const d of payload.detectors || []) {
    merged.secretRules.push({
      id: d.id,
      description: d.summary,
      family: d.family,
      source: 'gitguardian',
      severity: d.severity,
    });
  }
}

function mergeSonatype(merged, payload) {
  for (const adv of payload.advisories || []) {
    if (!adv.cve) continue;
    addCveAdvisory(merged, {
      cve: adv.cve, source: 'sonatype', summary: adv.title,
      severity: scoreToSeverity(adv.cvssScore),
      package: adv.purl, references: adv.reference ? [adv.reference] : [],
    });
  }
}

function mergePhylum(merged, payload) {
  merged.phylumAdvisories = payload.advisories || [];
}

function addCveAdvisory(merged, entry) {
  // Dedup by (cve, source); keep all sources so we can show provenance.
  const key = `${entry.cve}@${entry.source}`;
  if (merged._cveAdvisorySeen?.has?.(key)) return;
  merged._cveAdvisorySeen = merged._cveAdvisorySeen || new Set();
  merged._cveAdvisorySeen.add(key);
  merged.cveAdvisories.push(entry);
}

function scoreToSeverity(score) {
  if (score == null) return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Strip non-serializable internals before writing to disk.
 */
export function serialize(merged) {
  const out = { ...merged };
  delete out._cveAdvisorySeen;
  return out;
}
