import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ASTParser, NodeType, TokenType } from '../core/ast/parser.js';
import { ScopeTree, ScopeType } from '../core/ast/scope-tree.js';
import { TaintTracker } from '../core/ast/taint-tracker.js';
import { GuardrailDetector } from '../core/ast/guardrail-detector.js';

describe('Praxis AST & CST Parser', () => {
  it('tokenizes JavaScript code correctly', () => {
    const code = 'const apiKey = "sk-12345";\nfunction query(id) { return id; }';
    const { tokens, lines } = ASTParser.parse(code, 'app.js');
    assert.ok(tokens.length > 0);
    assert.equal(lines.length, 2);
    const keywords = tokens.filter(t => t.type === TokenType.KEYWORD);
    assert.ok(keywords.some(k => k.value === 'const'));
    assert.ok(keywords.some(k => k.value === 'function'));
  });

  it('parses Python functions, classes, and variables', () => {
    const pyCode = 'class Database:\n    def execute(self, query):\n        val = 42\n        return val';
    const { ast, lang } = ASTParser.parse(pyCode, 'db.py');
    assert.equal(lang, 'python');
    assert.equal(ast.type, NodeType.PROGRAM);
    assert.ok(ast.body.length > 0);
  });

  it('handles template literals and function calls in JavaScript', () => {
    const code = 'const sql = `SELECT * FROM users WHERE id = ${userId}`;\nexec(sql);';
    const { ast } = ASTParser.parse(code, 'server.js');
    assert.ok(ast.body.some(node => node.type === NodeType.VARIABLE_DECLARATION));
    assert.ok(ast.body.some(node => node.type === NodeType.CALL_EXPRESSION && node.callee === 'exec'));
  });

  it('is fault-tolerant and does not throw on syntax errors', () => {
    const brokenCode = 'function broken( { const x = ;';
    assert.doesNotThrow(() => {
      const { ast } = ASTParser.parse(brokenCode, 'broken.js');
      assert.ok(ast);
    });
  });
});

describe('Praxis ScopeTree & Symbol Resolver', () => {
  it('constructs lexical scopes and resolves parameters', () => {
    const code = `
function handler(req, res) {
  const userId = req.params.id;
  function internal() {
    const secret = "static_key";
  }
}
`;
    const { ast } = ASTParser.parse(code, 'handler.js');
    const tree = ScopeTree.build(ast, code);

    const fnScope = tree.getEnclosingFunction(3);
    assert.ok(fnScope);
    assert.equal(fnScope.name, 'handler');
    assert.ok(fnScope.variables.has('req'));
    assert.ok(fnScope.variables.has('res'));
    assert.ok(fnScope.variables.get('req').isParam);
  });

  it('detects static vs dynamic variables in scope', () => {
    const code = `
const API_KEY = "sk-fixed-constant-123";
let dynamicVar = "initial";
dynamicVar = process.env.TOKEN;
`;
    const { ast } = ASTParser.parse(code, 'config.js');
    const tree = ScopeTree.build(ast, code);

    assert.equal(tree.isVariableStatic('API_KEY', 2), true);
    assert.equal(tree.isVariableStatic('dynamicVar', 4), false);
  });

  it('detects try/catch blocks', () => {
    const code = `
try {
  dangerousOp();
} catch (err) {
  handleError(err);
}
`;
    const { ast } = ASTParser.parse(code, 'safe.js');
    const tree = ScopeTree.build(ast, code);
    assert.equal(tree.isInTryCatch(3), true);
  });
});

describe('Praxis Taint Tracker & Dataflow', () => {
  it('identifies direct untrusted input on sink lines', () => {
    const code = 'const result = exec(`ping ${req.query.host}`);';
    const result = TaintTracker.evaluateFinding({
      file: 'server.js',
      line: 1,
      matched: 'exec(`ping ${req.query.host}`)',
      code,
    });
    assert.equal(result.isTainted, true);
    assert.equal(result.isSanitized, false);
    assert.equal(result.confidenceAdjustment, 'confirm');
  });

  it('recognizes active sanitization (parseInt / DOMPurify) and downgrades', () => {
    const code = `
function getProfile(req) {
  const cleanId = parseInt(req.query.id);
  const query = \`SELECT * FROM users WHERE id = \${cleanId}\`;
}
`;
    const result = TaintTracker.evaluateFinding({
      file: 'profile.js',
      line: 4,
      matched: '`SELECT * FROM users WHERE id = ${cleanId}`',
      code,
    });
    assert.equal(result.isSanitized, true);
    assert.equal(result.confidenceAdjustment, 'downgrade');
  });

  it('recognizes comments and static string literals', () => {
    const code = '// db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);';
    const result = TaintTracker.evaluateFinding({
      file: 'test.js',
      line: 1,
      matched: 'db.query',
      code,
    });
    assert.equal(result.isStatic, true);
    assert.equal(result.confidenceAdjustment, 'low');
  });
});

describe('Praxis Guardrail & Defense Framework Detector', () => {
  it('detects NeMo Guardrails and Llama Guard in Python code', () => {
    const code = `
from nemoguardrails import RailsConfig, LLMRails
import llama_guard

rails = LLMRails(RailsConfig.from_path("./config"))
response = rails.generate(messages=[{"role": "user", "content": user_input}])
`;
    const analysis = GuardrailDetector.detect(code);
    assert.equal(analysis.hasGuardrails, true);
    assert.ok(analysis.frameworks.some(f => f.includes('NeMo')));
    assert.ok(analysis.frameworks.some(f => f.includes('Llama Guard')));
  });

  it('detects Instructor structured output and Zod schemas in JS/TS', () => {
    const code = `
import { z } from 'zod';
const UserSchema = z.object({ name: z.string(), email: z.string().email() });
const validated = UserSchema.safeParse(req.body);
`;
    const analysis = GuardrailDetector.detect(code);
    assert.equal(analysis.hasGuardrails, true);
    assert.ok(analysis.frameworks.some(f => f.includes('Zod')));
  });

  it('marks finding as protected when guardrail wraps the sink', () => {
    const code = `
import { LLMRails } from 'nemoguardrails';
const rails = new LLMRails();
const prompt = \`User: \${userPrompt}\`;
`;
    const finding = {
      rule: 'PROMPT_INJECTION_DIRECT',
      category: 'llm',
      line: 4,
    };
    const protection = GuardrailDetector.checkProtection(finding, code);
    assert.equal(protection.isProtected, true);
    assert.ok(protection.guardrail.includes('NeMo'));
  });
});
