/**
 * Praxis Taint Tracker & Dataflow Engine
 * =====================================
 *
 * Performs intra-file source-to-sink dataflow analysis to determine whether
 * dangerous sinks (SQL, Command execution, RAG ingestion, Prompt injection)
 * receive tainted untrusted input or safe/sanitized values.
 */

import { ASTParser } from './parser.js';
import { ScopeTree } from './scope-tree.js';

// =============================================================================
// PATTERNS & REGEXES
// =============================================================================

export const UNTRUSTED_SOURCES = [
  /\breq\.(?:body|query|params|headers|file|files|cookies)\b/,
  /\brequest\.(?:body|query|params|args|form|json|data|GET|POST|headers|files)\b/,
  /\bctx\.(?:request|query|params|body)\b/,
  /\bevent\.(?:body|queryStringParameters|headers)\b/,
  /\bsearchParams\.get\s*\(/,
  /\bformData\.(?:get|getAll)\s*\(/,
  /\bprocess\.argv\b/,
  /\bsys\.argv\b/,
  /\binput\s*\(/,
  /\b(?:userInput|user_input|userPayload|user_payload|userQuery|user_query|userPrompt|user_prompt|userMessage|user_message|rawInput|raw_input)\b/i,
];

export const SANITIZERS = [
  { name: 'parseInt/parseFloat/Number', regex: /\b(?:parseInt|parseFloat|Number|int|float)\s*\(/ },
  { name: 'DOMPurify', regex: /\bDOMPurify\.sanitize\s*\(/ },
  { name: 'sanitizeHtml', regex: /\bsanitize(?:Html)?\s*\(/i },
  { name: 'validator.escape', regex: /\bvalidator\.escape\s*\(/ },
  { name: 'encodeURIComponent', regex: /\bencodeURIComponent\s*\(/ },
  { name: 'shlex.quote', regex: /\bshlex\.quote\s*\(/ },
  { name: 'html.escape', regex: /\bhtml\.escape\s*\(/ },
  { name: 'schema.safeParse/Zod', regex: /\b(?:schema\.safeParse|safeParse|schema\.parse|zod|yup|ajv)\b/i },
  { name: 'parameterized/prepared', regex: /(?:\$1|\$\d+|\?|Prisma\.sql|prepared|bindValue|bindParam)/i },
];

export class TaintTracker {
  /**
   * Analyze dataflow for a finding's code context.
   *
   * @param {object} context — { file, line, matched, code, ast, scopeTree }
   * @returns {object} — { isTainted, isSanitized, isStatic, reason, confidenceAdjustment }
   */
  static evaluateFinding(context) {
    const { line, matched = '', code = '' } = context;
    const lines = code ? code.split('\n') : [];
    const findingLine = lines[line - 1] || matched;

    // ── 1. Comment check ──────────────────────────────────────────────────────
    if (/^\s*(?:\/\/|#|\*|\/\*|<!--)/.test(findingLine)) {
      return {
        isTainted: false,
        isSanitized: true,
        isStatic: true,
        reason: 'Finding is inside a comment line',
        confidenceAdjustment: 'low',
      };
    }

    // ── 2. Direct string literal / constant check ────────────────────────────
    if (/^['"][^'"]*['"]$/.test(matched.trim())) {
      return {
        isTainted: false,
        isSanitized: false,
        isStatic: true,
        reason: 'Value is a static string literal without interpolation',
        confidenceAdjustment: 'low',
      };
    }

    // ── 3. Check for immediate user input on the finding line ─────────────────
    const hasDirectUserInput = UNTRUSTED_SOURCES.some(src => src.test(findingLine));
    const hasDirectSanitization = SANITIZERS.some(s => s.regex.test(findingLine));

    if (hasDirectSanitization && !hasDirectUserInput) {
      return {
        isTainted: false,
        isSanitized: true,
        isStatic: false,
        reason: 'Finding is wrapped in active sanitization/validation logic',
        confidenceAdjustment: 'low',
      };
    }

    // ── 4. AST Scope-based upstream trace ─────────────────────────────────────
    let scopeTree = context.scopeTree;
    if (!scopeTree && code) {
      const parsed = ASTParser.parse(code, context.file || '');
      scopeTree = ScopeTree.build(parsed.ast, code);
    }

    if (scopeTree) {
      const scope = scopeTree.getScopeAt(line);
      const encFn = scopeTree.getEnclosingFunction(line);
      const inTryCatch = scopeTree.isInTryCatch(line);

      // Check the lines within the enclosing scope (not bleeding into other functions)
      const startLine = scope.range.startLine;
      const endLine = Math.min(line, scope.range.endLine);
      const upstreamLines = lines.slice(startLine - 1, endLine - 1);
      const upstreamText = upstreamLines.join('\n');

      const hasScopeUserInput = UNTRUSTED_SOURCES.some(src => src.test(upstreamText));
      const matchedSanitizer = SANITIZERS.find(s => s.regex.test(upstreamText));

      if (matchedSanitizer && !hasDirectUserInput) {
        return {
          isTainted: false,
          isSanitized: true,
          isStatic: false,
          sanitizer: matchedSanitizer.name,
          reason: `Sanitization detected in enclosing scope via ${matchedSanitizer.name}`,
          confidenceAdjustment: 'downgrade',
        };
      }

      if (hasScopeUserInput || hasDirectUserInput || encFn?.params?.length > 0) {
        return {
          isTainted: true,
          isSanitized: false,
          isStatic: false,
          inTryCatch,
          reason: 'Untrusted user input flows into this sink within function scope',
          confidenceAdjustment: 'confirm',
        };
      }

      // Check if variables referenced in matched text are static in scope
      const idMatches = matched.match(/[a-zA-Z_$][a-zA-Z0-9_$]*/g) || [];
      const staticVars = idMatches.filter(id => scopeTree.isVariableStatic(id, line));
      if (staticVars.length > 0 && !hasScopeUserInput) {
        return {
          isTainted: false,
          isSanitized: false,
          isStatic: true,
          reason: `Referenced variable(s) [${staticVars.join(', ')}] are statically initialized constants`,
          confidenceAdjustment: 'downgrade',
        };
      }
    }

    // Default neutral
    return {
      isTainted: hasDirectUserInput,
      isSanitized: hasDirectSanitization,
      isStatic: false,
      reason: 'Standard pattern match',
      confidenceAdjustment: null,
    };
  }
}

export default TaintTracker;
