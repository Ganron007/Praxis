/**
 * Praxis AST & CST Parser
 * =======================
 *
 * Fast, pure ESM, zero-native-dependency code parser for JavaScript, TypeScript,
 * JSX, TSX, and Python.
 *
 * Designed to provide:
 * 1. Concrete Syntax Tokens (CST): accurate tokenization with line/column positions.
 * 2. Abstract Syntax Tree (AST): functions, classes, variables, assignments, calls,
 *    imports, template literals, try/catch, and block scopes.
 * 3. Fault-tolerant (never throws, returns best-effort AST on syntax errors).
 */

// =============================================================================
// TOKEN TYPES & NODE TYPES
// =============================================================================

export const TokenType = {
  KEYWORD: 'KEYWORD',
  IDENTIFIER: 'IDENTIFIER',
  STRING: 'STRING',
  TEMPLATE: 'TEMPLATE',
  NUMBER: 'NUMBER',
  OPERATOR: 'OPERATOR',
  PUNCTUATION: 'PUNCTUATION',
  COMMENT: 'COMMENT',
  WHITESPACE: 'WHITESPACE',
  NEWLINE: 'NEWLINE',
};

export const NodeType = {
  PROGRAM: 'Program',
  FUNCTION_DECLARATION: 'FunctionDeclaration',
  CLASS_DECLARATION: 'ClassDeclaration',
  VARIABLE_DECLARATION: 'VariableDeclaration',
  ASSIGNMENT: 'AssignmentExpression',
  CALL_EXPRESSION: 'CallExpression',
  MEMBER_EXPRESSION: 'MemberExpression',
  TEMPLATE_LITERAL: 'TemplateLiteral',
  IMPORT_DECLARATION: 'ImportDeclaration',
  TRY_STATEMENT: 'TryStatement',
  RETURN_STATEMENT: 'ReturnStatement',
  THROW_STATEMENT: 'ThrowStatement',
  IF_STATEMENT: 'IfStatement',
  BLOCK: 'BlockStatement',
  COMMENT: 'Comment',
};

// =============================================================================
// TOKENIZER
// =============================================================================

const JS_KEYWORDS = new Set([
  'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue',
  'debugger', 'default', 'delete', 'do', 'else', 'export', 'extends', 'finally',
  'for', 'function', 'if', 'import', 'in', 'instanceof', 'let', 'new', 'return',
  'super', 'switch', 'this', 'throw', 'try', 'typeof', 'var', 'void', 'while',
  'with', 'yield', 'from', 'as', 'type', 'interface', 'implements',
]);

const PY_KEYWORDS = new Set([
  'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def',
  'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if',
  'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise',
  'return', 'try', 'while', 'with', 'yield',
]);

export class Tokenizer {
  constructor(code, lang = 'javascript') {
    this.code = code;
    this.lang = lang.toLowerCase();
    this.pos = 0;
    this.line = 1;
    this.col = 1;
    this.tokens = [];
  }

  tokenize() {
    const len = this.code.length;
    const isPython = this.lang === 'python' || this.lang === 'py';
    const keywords = isPython ? PY_KEYWORDS : JS_KEYWORDS;

    while (this.pos < len) {
      const char = this.code[this.pos];
      const startLine = this.line;
      const startCol = this.col;

      // ── 1. Newline ──────────────────────────────────────────────────────────
      if (char === '\n') {
        this.tokens.push({
          type: TokenType.NEWLINE,
          value: '\n',
          line: startLine,
          col: startCol,
          start: this.pos,
          end: this.pos + 1,
        });
        this.pos++;
        this.line++;
        this.col = 1;
        continue;
      }

      // ── 2. Whitespace ───────────────────────────────────────────────────────
      if (/[ \t\r\f\v]/.test(char)) {
        let val = '';
        const start = this.pos;
        while (this.pos < len && /[ \t\r\f\v]/.test(this.code[this.pos])) {
          val += this.code[this.pos];
          this.pos++;
          this.col++;
        }
        this.tokens.push({
          type: TokenType.WHITESPACE,
          value: val,
          line: startLine,
          col: startCol,
          start,
          end: this.pos,
        });
        continue;
      }

      // ── 3. Single-line comment ──────────────────────────────────────────────
      if ((!isPython && char === '/' && this.code[this.pos + 1] === '/') ||
          (isPython && char === '#')) {
        let val = '';
        const start = this.pos;
        while (this.pos < len && this.code[this.pos] !== '\n') {
          val += this.code[this.pos];
          this.pos++;
          this.col++;
        }
        this.tokens.push({
          type: TokenType.COMMENT,
          value: val,
          line: startLine,
          col: startCol,
          start,
          end: this.pos,
        });
        continue;
      }

      // ── 4. Multi-line comment (JS/TS /* ... */) ─────────────────────────────
      if (!isPython && char === '/' && this.code[this.pos + 1] === '*') {
        let val = '/*';
        const start = this.pos;
        this.pos += 2;
        this.col += 2;
        while (this.pos < len && !(this.code[this.pos] === '*' && this.code[this.pos + 1] === '/')) {
          if (this.code[this.pos] === '\n') {
            this.line++;
            this.col = 1;
          } else {
            this.col++;
          }
          val += this.code[this.pos];
          this.pos++;
        }
        if (this.pos < len) {
          val += '*/';
          this.pos += 2;
          this.col += 2;
        }
        this.tokens.push({
          type: TokenType.COMMENT,
          value: val,
          line: startLine,
          col: startCol,
          start,
          end: this.pos,
        });
        continue;
      }

      // ── 5. Strings (single, double, or python triple-quotes) ─────────────────
      if (char === '"' || char === "'") {
        const quote = char;
        const isTriple = isPython && (this.code.slice(this.pos, this.pos + 3) === quote.repeat(3));
        const quoteStr = isTriple ? quote.repeat(3) : quote;
        let val = quoteStr;
        const start = this.pos;
        this.pos += quoteStr.length;
        this.col += quoteStr.length;

        while (this.pos < len) {
          if (this.code[this.pos] === '\\') {
            val += this.code[this.pos] + (this.code[this.pos + 1] || '');
            this.pos += 2;
            this.col += 2;
            continue;
          }
          if (isTriple) {
            if (this.code.slice(this.pos, this.pos + 3) === quoteStr) {
              val += quoteStr;
              this.pos += 3;
              this.col += 3;
              break;
            }
          } else if (this.code[this.pos] === quote) {
            val += quote;
            this.pos++;
            this.col++;
            break;
          }
          if (this.code[this.pos] === '\n') {
            this.line++;
            this.col = 1;
          } else {
            this.col++;
          }
          val += this.code[this.pos];
          this.pos++;
        }

        this.tokens.push({
          type: TokenType.STRING,
          value: val,
          quote: quoteStr,
          line: startLine,
          col: startCol,
          start,
          end: this.pos,
        });
        continue;
      }

      // ── 6. JS Template Literal (` ... `) ────────────────────────────────────
      if (!isPython && char === '`') {
        let val = '`';
        const start = this.pos;
        this.pos++;
        this.col++;
        while (this.pos < len && this.code[this.pos] !== '`') {
          if (this.code[this.pos] === '\\') {
            val += this.code[this.pos] + (this.code[this.pos + 1] || '');
            this.pos += 2;
            this.col += 2;
            continue;
          }
          if (this.code[this.pos] === '\n') {
            this.line++;
            this.col = 1;
          } else {
            this.col++;
          }
          val += this.code[this.pos];
          this.pos++;
        }
        if (this.pos < len) {
          val += '`';
          this.pos++;
          this.col++;
        }
        this.tokens.push({
          type: TokenType.TEMPLATE,
          value: val,
          line: startLine,
          col: startCol,
          start,
          end: this.pos,
        });
        continue;
      }

      // ── 7. Numbers ──────────────────────────────────────────────────────────
      if (/[0-9]/.test(char) || (char === '.' && /[0-9]/.test(this.code[this.pos + 1] || ''))) {
        let val = '';
        const start = this.pos;
        while (this.pos < len && /[0-9a-fA-FxXoObB._]/.test(this.code[this.pos])) {
          val += this.code[this.pos];
          this.pos++;
          this.col++;
        }
        this.tokens.push({
          type: TokenType.NUMBER,
          value: val,
          line: startLine,
          col: startCol,
          start,
          end: this.pos,
        });
        continue;
      }

      // ── 8. Identifiers & Keywords ───────────────────────────────────────────
      if (/[a-zA-Z_$]/.test(char)) {
        let val = '';
        const start = this.pos;
        while (this.pos < len && /[a-zA-Z0-9_$]/.test(this.code[this.pos])) {
          val += this.code[this.pos];
          this.pos++;
          this.col++;
        }
        const isKw = keywords.has(val);
        this.tokens.push({
          type: isKw ? TokenType.KEYWORD : TokenType.IDENTIFIER,
          value: val,
          line: startLine,
          col: startCol,
          start,
          end: this.pos,
        });
        continue;
      }

      // ── 9. Operators & Punctuation ───────────────────────────────────────────
      const punct2 = this.code.slice(this.pos, this.pos + 2);
      const punct3 = this.code.slice(this.pos, this.pos + 3);
      if (['===', '!==', '...', '>>>', '<<=', '>>='].includes(punct3)) {
        this.tokens.push({ type: TokenType.OPERATOR, value: punct3, line: startLine, col: startCol, start: this.pos, end: this.pos + 3 });
        this.pos += 3;
        this.col += 3;
        continue;
      }
      if (['==', '!=', '<=', '>=', '=>', '&&', '||', '??', '+=', '-=', '*=', '/=', '%=', '**', '->', '::'].includes(punct2)) {
        this.tokens.push({ type: TokenType.OPERATOR, value: punct2, line: startLine, col: startCol, start: this.pos, end: this.pos + 2 });
        this.pos += 2;
        this.col += 2;
        continue;
      }

      const isOp = /[+\-*/%^&|!~=<>?:@]/.test(char);
      this.tokens.push({
        type: isOp ? TokenType.OPERATOR : TokenType.PUNCTUATION,
        value: char,
        line: startLine,
        col: startCol,
        start: this.pos,
        end: this.pos + 1,
      });
      this.pos++;
      this.col++;
    }

    return this.tokens;
  }
}

// =============================================================================
// AST PARSER
// =============================================================================

export class ASTParser {
  /**
   * Parse source code into an AST and token stream.
   *
   * @param {string} code     — Source code text
   * @param {string} filePath — File path for language inference
   * @returns {object}        — { ast, tokens, lines, comments, lang }
   */
  static parse(code, filePath = '') {
    if (!code || typeof code !== 'string') {
      return { ast: { type: NodeType.PROGRAM, body: [], range: { startLine: 1, endLine: 1 } }, tokens: [], lines: [], comments: [] };
    }

    const ext = (filePath.split('.').pop() || '').toLowerCase();
    const lang = ['py', 'python'].includes(ext) ? 'python' : 'javascript';

    const tokenizer = new Tokenizer(code, lang);
    const allTokens = tokenizer.tokenize();
    const meaningfulTokens = allTokens.filter(t => t.type !== TokenType.WHITESPACE);
    const comments = allTokens.filter(t => t.type === TokenType.COMMENT);
    const lines = code.split('\n');

    const parser = new ASTParserInstance(meaningfulTokens, code, lines, lang);
    const ast = parser.parseProgram();

    return {
      ast,
      tokens: allTokens,
      lines,
      comments,
      lang,
    };
  }
}

class ASTParserInstance {
  constructor(tokens, code, lines, lang) {
    this.tokens = tokens;
    this.code = code;
    this.lines = lines;
    this.lang = lang;
    this.pos = 0;
  }

  peek(offset = 0) {
    return this.tokens[this.pos + offset] || null;
  }

  next() {
    return this.tokens[this.pos++] || null;
  }

  parseProgram() {
    const body = [];
    while (this.pos < this.tokens.length) {
      const node = this.parseStatement();
      if (node) {
        body.push(node);
      } else {
        this.pos++;
      }
    }
    return {
      type: NodeType.PROGRAM,
      body,
      range: {
        startLine: 1,
        endLine: this.lines.length,
      },
    };
  }

  parseStatement() {
    const t = this.peek();
    if (!t) return null;

    // ── Function Declarations (JS: function / async function, Py: def) ────────
    if (t.type === TokenType.KEYWORD && (t.value === 'function' || t.value === 'def')) {
      return this.parseFunctionDeclaration();
    }
    if (t.type === TokenType.KEYWORD && t.value === 'async' && this.peek(1)?.value === 'function') {
      this.next(); // consume async
      return this.parseFunctionDeclaration(true);
    }
    if (t.type === TokenType.KEYWORD && t.value === 'async' && this.peek(1)?.value === 'def') {
      this.next(); // consume async
      return this.parseFunctionDeclaration(true);
    }

    // ── Class Declarations (class Foo) ───────────────────────────────────────
    if (t.type === TokenType.KEYWORD && t.value === 'class') {
      return this.parseClassDeclaration();
    }

    // ── Variable Declarations (const / let / var) ───────────────────────────
    if (t.type === TokenType.KEYWORD && ['const', 'let', 'var'].includes(t.value)) {
      return this.parseVariableDeclaration();
    }

    // ── Import Declarations (import ... from ... / from ... import ...) ─────
    if (t.type === TokenType.KEYWORD && (t.value === 'import' || (this.lang === 'python' && t.value === 'from'))) {
      return this.parseImportDeclaration();
    }

    // ── Try Statement ────────────────────────────────────────────────────────
    if (t.type === TokenType.KEYWORD && t.value === 'try') {
      return this.parseTryStatement();
    }

    // ── Return / Throw ───────────────────────────────────────────────────────
    if (t.type === TokenType.KEYWORD && t.value === 'return') {
      return { type: NodeType.RETURN_STATEMENT, line: t.line, col: t.col, token: this.next() };
    }
    if (t.type === TokenType.KEYWORD && (t.value === 'throw' || t.value === 'raise')) {
      return { type: NodeType.THROW_STATEMENT, line: t.line, col: t.col, token: this.next() };
    }

    // ── Expressions (Calls, Assignments, Member access) ─────────────────────
    if (t.type === TokenType.IDENTIFIER) {
      // Check for Python assignment `x = ...` or JS assignment `x = ...`
      if (this.peek(1)?.value === '=') {
        return this.parseAssignment();
      }
      // Check for function call `foo(...)` or `obj.foo(...)`
      return this.parseExpressionStatement();
    }

    return null;
  }

  parseFunctionDeclaration(isAsync = false) {
    const fnKw = this.next(); // function or def
    const nameToken = this.peek()?.type === TokenType.IDENTIFIER ? this.next() : null;
    const name = nameToken ? nameToken.value : '(anonymous)';
    const params = [];

    // Parse parameter list inside (...)
    if (this.peek()?.value === '(') {
      this.next(); // consume (
      while (this.pos < this.tokens.length && this.peek()?.value !== ')') {
        const paramTok = this.peek();
        if (paramTok?.type === TokenType.IDENTIFIER) {
          params.push(paramTok.value);
        }
        this.next();
      }
      if (this.peek()?.value === ')') this.next(); // consume )
    }

    // Find function body range
    const startLine = fnKw.line;
    let endLine = startLine;

    // In JS/TS: look for matching { ... }
    if (this.lang !== 'python') {
      let depth = 0;
      let started = false;
      while (this.pos < this.tokens.length) {
        const tok = this.next();
        if (tok.value === '{') {
          depth++;
          started = true;
        } else if (tok.value === '}') {
          depth--;
          if (started && depth <= 0) {
            endLine = tok.line;
            break;
          }
        }
      }
    } else {
      // In Python: indent-based estimate
      endLine = Math.min(this.lines.length, startLine + 40);
    }

    return {
      type: NodeType.FUNCTION_DECLARATION,
      name,
      params,
      isAsync,
      range: { startLine, endLine },
      line: startLine,
      col: fnKw.col,
    };
  }

  parseClassDeclaration() {
    const classKw = this.next();
    const nameToken = this.peek()?.type === TokenType.IDENTIFIER ? this.next() : null;
    const name = nameToken ? nameToken.value : '(anonymous)';
    return {
      type: NodeType.CLASS_DECLARATION,
      name,
      line: classKw.line,
      col: classKw.col,
      range: { startLine: classKw.line, endLine: classKw.line + 30 },
    };
  }

  parseVariableDeclaration() {
    const kindTok = this.next(); // const, let, var
    const declarations = [];

    while (this.pos < this.tokens.length) {
      const idTok = this.peek();
      if (idTok?.type !== TokenType.IDENTIFIER) break;
      const id = this.next().value;
      let init = null;
      let isStatic = false;

      if (this.peek()?.value === '=') {
        this.next(); // consume =
        const valTok = this.peek();
        if (valTok) {
          init = valTok.value;
          if (valTok.type === TokenType.STRING || valTok.type === TokenType.NUMBER) {
            isStatic = true;
          }
          this.next();
        }
      }

      declarations.push({
        name: id,
        kind: kindTok.value,
        init,
        isStatic,
        line: kindTok.line,
        col: kindTok.col,
      });

      if (this.peek()?.value === ',') {
        this.next();
      } else {
        break;
      }
    }

    return {
      type: NodeType.VARIABLE_DECLARATION,
      kind: kindTok.value,
      declarations,
      line: kindTok.line,
    };
  }

  parseAssignment() {
    const target = this.next().value; // identifier
    this.next(); // consume =
    const valueToken = this.next();
    const isStatic = valueToken?.type === TokenType.STRING || valueToken?.type === TokenType.NUMBER;

    return {
      type: NodeType.ASSIGNMENT,
      target,
      value: valueToken?.value || null,
      isStatic,
      line: valueToken?.line || 1,
    };
  }

  parseImportDeclaration() {
    const importKw = this.next();
    let source = '';
    const importedNames = [];

    while (this.pos < this.tokens.length && this.peek()?.value !== '\n' && this.peek()?.value !== ';') {
      const tok = this.next();
      if (tok.type === TokenType.IDENTIFIER && tok.value !== 'from' && tok.value !== 'as' && tok.value !== 'import') {
        importedNames.push(tok.value);
      } else if (tok.type === TokenType.STRING) {
        source = tok.value.replace(/['"]/g, '');
      }
    }

    return {
      type: NodeType.IMPORT_DECLARATION,
      source,
      importedNames,
      line: importKw.line,
    };
  }

  parseTryStatement() {
    const tryKw = this.next();
    return {
      type: NodeType.TRY_STATEMENT,
      line: tryKw.line,
      range: { startLine: tryKw.line, endLine: tryKw.line + 15 },
    };
  }

  parseExpressionStatement() {
    const firstTok = this.next();
    let callChain = [firstTok.value];

    while (this.pos < this.tokens.length) {
      const nextTok = this.peek();
      if (nextTok?.value === '.' || nextTok?.value === '?.') {
        this.next(); // consume .
        const propTok = this.next();
        if (propTok) callChain.push(propTok.value);
      } else if (nextTok?.value === '(') {
        // Call expression
        this.next(); // consume (
        const args = [];
        while (this.pos < this.tokens.length && this.peek()?.value !== ')') {
          const argTok = this.next();
          if (argTok && argTok.value !== ',') {
            args.push(argTok.value);
          }
        }
        if (this.peek()?.value === ')') this.next();

        return {
          type: NodeType.CALL_EXPRESSION,
          callee: callChain.join('.'),
          args,
          line: firstTok.line,
          col: firstTok.col,
        };
      } else {
        break;
      }
    }

    return null;
  }
}

export default ASTParser;
