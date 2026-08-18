/**
 * Praxis Accuracy & Benchmark Harness
 * ===================================
 *
 * Runs ground-truth benchmark fixtures through scanners and verifiers
 * to calculate precision, recall, false-positive rate, and F1 score.
 */

import { GROUND_TRUTH_FIXTURES } from './fixtures.js';
import { ASTParser, ScopeTree, TaintTracker, GuardrailDetector } from '../../core/ast/index.js';

export class BenchmarkRunner {
  static run(fixtures = GROUND_TRUTH_FIXTURES) {
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    const results = [];

    for (const fixture of fixtures) {
      const code = fixture.code;
      const parsed = ASTParser.parse(code, fixture.language === 'python' ? 'test.py' : 'test.js');
      const scopeTree = ScopeTree.build(parsed.ast, code);

      // Evaluate dataflow and guardrails
      const lines = code.split('\n');
      let flagged = false;
      let flaggedReason = '';

      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i];
        const lineNum = i + 1;

        // Skip comments
        if (/^\s*(?:\/\/|#|\*|\/\*)/.test(lineText)) continue;

        // Check if line matches dangerous pattern signatures
        const hasSink = /(?:exec(?:Sync)?\s*\(\s*`|(?:\$queryRaw|\.raw|knex\.raw|db\.query|\.query)\s*\(|pickle\.loads|addDocuments|generate|`[^`]*\$\{)/i.test(lineText);
        if (hasSink) {
          const taint = TaintTracker.evaluateFinding({
            file: fixture.language === 'python' ? 'test.py' : 'test.js',
            line: lineNum,
            matched: lineText.trim(),
            code,
            scopeTree,
          });

          const guard = GuardrailDetector.checkProtection(
            { rule: fixture.rule, category: fixture.category, line: lineNum },
            code
          );

          if (!guard.isProtected && !taint.isSanitized && !taint.isStatic && (taint.isTainted || taint.confidenceAdjustment === 'confirm')) {
            flagged = true;
            flaggedReason = taint.reason || 'Confirmed tainted sink';
            break;
          }
        }
      }

      const isVulnerable = fixture.expectedVulnerable;
      let classification = '';

      if (isVulnerable && flagged) {
        tp++;
        classification = 'TP (True Positive)';
      } else if (!isVulnerable && flagged) {
        fp++;
        classification = 'FP (False Positive)';
      } else if (!isVulnerable && !flagged) {
        tn++;
        classification = 'TN (True Negative)';
      } else if (isVulnerable && !flagged) {
        fn++;
        classification = 'FN (False Negative)';
      }

      results.push({
        id: fixture.id,
        expected: isVulnerable,
        actual: flagged,
        classification,
        reason: flaggedReason,
      });
    }

    const precision = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 100;
    const recall = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 100;
    const fpr = fp + tn > 0 ? (fp / (fp + tn)) * 100 : 0;
    const f1 = precision + recall > 0 ? (2 * (precision * recall)) / (precision + recall) : 0;

    return {
      metrics: {
        total: fixtures.length,
        tp,
        fp,
        tn,
        fn,
        precision: Number(precision.toFixed(1)),
        recall: Number(recall.toFixed(1)),
        falsePositiveRate: Number(fpr.toFixed(1)),
        f1Score: Number(f1.toFixed(1)),
      },
      results,
    };
  }
}

export default BenchmarkRunner;
