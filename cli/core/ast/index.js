/**
 * Praxis AST & Dataflow Engine
 * =============================
 *
 * Unified export surface for:
 * - ASTParser (fast JavaScript/TypeScript & Python tokenizer and parser)
 * - ScopeTree (lexical scope tree & symbol resolution)
 * - TaintTracker (source-to-sink dataflow analysis)
 * - GuardrailDetector (AI runtime defense & guardrail detection)
 */

export { ASTParser, Tokenizer, TokenType, NodeType } from './parser.js';
export { ScopeTree, Scope, ScopeType } from './scope-tree.js';
export { TaintTracker, UNTRUSTED_SOURCES, SANITIZERS } from './taint-tracker.js';
export { GuardrailDetector, GUARDRAIL_FRAMEWORKS } from './guardrail-detector.js';

export default {
  ASTParser: import('./parser.js').then(m => m.ASTParser),
  ScopeTree: import('./scope-tree.js').then(m => m.ScopeTree),
  TaintTracker: import('./taint-tracker.js').then(m => m.TaintTracker),
  GuardrailDetector: import('./guardrail-detector.js').then(m => m.GuardrailDetector),
};
