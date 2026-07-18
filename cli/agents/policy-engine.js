/**
 * Policy-as-Code Engine
 * ======================
 *
 * Enforces security policies defined in .praxis.policy.json.
 * Teams can define minimum scores, required scans, severity thresholds,
 * and custom rule overrides.
 *
 * USAGE:
 *   const policy = PolicyEngine.load(rootPath);
 *   const violations = policy.evaluate(scoreResult, findings);
 */

import fs from 'fs';
import path from 'path';

const DEFAULT_POLICY = {
  minimumScore: 0,
  failOn: null,           // 'critical' | 'high' | 'medium' — fail if any finding at this level
  requiredScans: [],      // ['secrets', 'deps', 'injection', 'auth']
  ignoreRules: [],        // ['GENERIC_API_KEY', 'API_NO_VALIDATION']
  customSeverityOverrides: {}, // { 'CORS_WILDCARD': 'critical' }
  maxAge: {
    criticalCVE: null,    // '7d' — max time before critical CVEs must be fixed
    highCVE: null,
    mediumCVE: null,
  },
};

export class PolicyEngine {
  constructor(policy = {}) {
    this.policy = { ...DEFAULT_POLICY, ...policy };
  }

  /**
   * Load policy from .praxis.policy.json in the project root.
   */
  static load(rootPath) {
    const policyPath = path.join(rootPath, '.praxis.policy.json');

    if (!fs.existsSync(policyPath)) {
      return new PolicyEngine();
    }

    try {
      const content = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
      return new PolicyEngine(content);
    } catch (err) {
      console.warn(`Warning: Could not parse .praxis.policy.json: ${err.message}`);
      return new PolicyEngine();
    }
  }

  /**
   * Evaluate findings against the policy.
   * Returns array of violations (empty = pass).
   */
  evaluate(scoreResult, findings = [], options = {}) {
    const violations = [];

    // ── Minimum score check ───────────────────────────────────────────────────
    if (this.policy.minimumScore > 0 && scoreResult.score < this.policy.minimumScore) {
      violations.push({
        type: 'minimum_score',
        message: `Score ${scoreResult.score} is below minimum ${this.policy.minimumScore}`,
        severity: 'critical',
      });
    }

    // ── Fail-on severity check ────────────────────────────────────────────────
    if (this.policy.failOn) {
      const sevOrder = ['critical', 'high', 'medium', 'low'];
      const threshold = sevOrder.indexOf(this.policy.failOn);

      for (const finding of findings) {
        const findingSev = sevOrder.indexOf(finding.severity);
        if (findingSev >= 0 && findingSev <= threshold) {
          violations.push({
            type: 'severity_threshold',
            message: `${finding.severity} finding: ${finding.title} in ${finding.file}:${finding.line}`,
            severity: finding.severity,
            finding,
          });
        }
      }
    }

    // ── Required Scans Check ──────────────────────────────────────────────────
    if (this.policy.requiredScans && this.policy.requiredScans.length > 0) {
      const runCategories = new Set(
        (options.agentResults || [])
          .filter(r => r.success)
          .map(r => r.category ? r.category.toLowerCase() : r.agent ? r.agent.toLowerCase() : '')
      );
      
      if (options.depsRun) {
        runCategories.add('deps');
      }
      if (options.secretsRun) {
        runCategories.add('secrets');
      }

      for (const scan of this.policy.requiredScans) {
        const scanLower = scan.toLowerCase();
        if (!runCategories.has(scanLower)) {
          violations.push({
            type: 'missing_scan',
            message: `Required security scan "${scan}" was not run or failed`,
            severity: 'high',
          });
        }
      }
    }

    // ── CVE Max Age (SLA) Check ───────────────────────────────────────────────
    if (this.policy.maxAge && options.depVulns) {
      const isOlderThan = (dateStr, durationStr) => {
        if (!dateStr || !durationStr) return false;
        const publishedDate = new Date(dateStr);
        if (Number.isNaN(publishedDate.getTime())) return false;
        const match = durationStr.match(/^(\d+)([dhmys])$/i);
        if (!match) return false;
        const val = parseInt(match[1], 10);
        const unit = match[2].toLowerCase();
        const mult = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[unit] || 86400000;
        return (Date.now() - publishedDate.getTime()) > val * mult;
      };

      for (const vuln of options.depVulns) {
        const severity = vuln.severity?.toLowerCase();
        const policyKey = `${severity}CVE`;
        const duration = this.policy.maxAge[policyKey];
        if (!duration) continue;

        let violated = false;
        let reason = '';

        if (vuln.published) {
          if (isOlderThan(vuln.published, duration)) {
            violated = true;
            const ageDays = Math.round((Date.now() - new Date(vuln.published).getTime()) / 86400000);
            reason = `${vuln.name} vulnerability ${vuln.cve || ''} is ${ageDays} days old (exceeds SLA of ${duration})`;
          }
        } else if (vuln.cve) {
          const m = vuln.cve.match(/^CVE-(\d{4})-\d+/i);
          if (m) {
            const year = parseInt(m[1], 10);
            const currentYear = new Date().getFullYear();
            if (currentYear - year >= 2) {
              violated = true;
              reason = `${vuln.name} vulnerability ${vuln.cve} is from ${year} (exceeds SLA of ${duration})`;
            }
          }
        }

        if (violated) {
          violations.push({
            type: 'cve_sla_breach',
            message: reason,
            severity: severity === 'critical' ? 'critical' : 'high',
            vuln,
          });
        }
      }
    }

    return violations;
  }

  /**
   * Check if a finding's rule should be ignored by policy.
   */
  isIgnored(finding) {
    return this.policy.ignoreRules.includes(finding.rule);
  }

  /**
   * Apply severity overrides from policy.
   */
  applySeverityOverrides(findings) {
    return findings.map(f => {
      if (this.policy.customSeverityOverrides[f.rule]) {
        return { ...f, severity: this.policy.customSeverityOverrides[f.rule] };
      }
      return f;
    });
  }

  /**
   * Filter findings by policy ignores and apply overrides.
   */
  applyPolicy(findings) {
    let filtered = findings.filter(f => !this.isIgnored(f));
    filtered = this.applySeverityOverrides(filtered);
    return filtered;
  }

  /**
   * Check if policy passes (no violations).
   */
  passes(scoreResult, findings, options = {}) {
    return this.evaluate(scoreResult, findings, options).length === 0;
  }

  /**
   * Generate a default policy template.
   */
  static generateTemplate(rootPath) {
    const template = {
      minimumScore: 70,
      failOn: 'critical',
      requiredScans: ['secrets', 'injection', 'deps', 'auth'],
      ignoreRules: [],
      customSeverityOverrides: {},
      maxAge: {
        criticalCVE: '7d',
        highCVE: '30d',
        mediumCVE: '90d',
      },
    };

    const policyPath = path.join(rootPath, '.praxis.policy.json');
    fs.writeFileSync(policyPath, JSON.stringify(template, null, 2));
    return policyPath;
  }
}

export default PolicyEngine;
