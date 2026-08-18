/**
 * Praxis Scope Tree & Symbol Resolver
 * ===================================
 *
 * Constructs lexical scopes and resolves symbols across JavaScript,
 * TypeScript, and Python codebases.
 *
 * Provides:
 * 1. Scope hierarchy: Global, Function, Class, Block, TryCatch.
 * 2. Symbol resolution: declarations, parameter origin, constant folding,
 *    and variable mutation tracking.
 * 3. Enclosing scope queries: `getScopeAt(line)` for accurate block boundaries.
 */

import { NodeType } from './parser.js';

export const ScopeType = {
  GLOBAL: 'GLOBAL',
  FUNCTION: 'FUNCTION',
  CLASS: 'CLASS',
  BLOCK: 'BLOCK',
  TRY_CATCH: 'TRY_CATCH',
};

export class Scope {
  constructor(type, range, parent = null, name = '') {
    this.type = type;
    this.name = name;
    this.range = range || { startLine: 1, endLine: 100000 };
    this.parent = parent;
    this.children = [];
    this.variables = new Map(); // name -> { kind, init, isStatic, line, isParam, sanitized }
    this.imports = new Map();   // name -> { source, importedName, line }
  }

  containsLine(line) {
    return line >= this.range.startLine && line <= this.range.endLine;
  }

  addVariable(name, info) {
    this.variables.set(name, {
      name,
      kind: info.kind || 'var',
      init: info.init || null,
      isStatic: info.isStatic ?? false,
      line: info.line || 1,
      isParam: info.isParam ?? false,
      sanitized: info.sanitized ?? false,
      assignments: info.assignments || [],
    });
  }

  addImport(localName, info) {
    this.imports.set(localName, info);
  }

  lookupVariable(name) {
    if (this.variables.has(name)) {
      return this.variables.get(name);
    }
    if (this.parent) {
      return this.parent.lookupVariable(name);
    }
    return null;
  }

  lookupImport(name) {
    if (this.imports.has(name)) {
      return this.imports.get(name);
    }
    if (this.parent) {
      return this.parent.lookupImport(name);
    }
    return null;
  }
}

export class ScopeTree {
  constructor(ast, code = '') {
    this.ast = ast;
    this.code = code;
    this.globalScope = new Scope(ScopeType.GLOBAL, ast?.range || { startLine: 1, endLine: 10000 });
    this._buildTree();
  }

  static build(ast, code = '') {
    return new ScopeTree(ast, code);
  }

  _buildTree() {
    if (!this.ast || !this.ast.body) return;

    for (const node of this.ast.body) {
      this._processNode(node, this.globalScope);
    }
  }

  _processNode(node, currentScope) {
    if (!node) return;

    switch (node.type) {
      case NodeType.FUNCTION_DECLARATION: {
        const fnScope = new Scope(
          ScopeType.FUNCTION,
          node.range,
          currentScope,
          node.name
        );
        currentScope.children.push(fnScope);
        currentScope.addVariable(node.name, {
          kind: 'function',
          init: node.name,
          isStatic: true,
          line: node.line,
        });

        // Register parameters
        if (Array.isArray(node.params)) {
          for (const param of node.params) {
            fnScope.addVariable(param, {
              kind: 'param',
              init: null,
              isStatic: false,
              isParam: true,
              line: node.line,
            });
          }
        }
        break;
      }

      case NodeType.CLASS_DECLARATION: {
        const classScope = new Scope(
          ScopeType.CLASS,
          node.range,
          currentScope,
          node.name
        );
        currentScope.children.push(classScope);
        currentScope.addVariable(node.name, {
          kind: 'class',
          init: node.name,
          isStatic: true,
          line: node.line,
        });
        break;
      }

      case NodeType.VARIABLE_DECLARATION: {
        if (Array.isArray(node.declarations)) {
          for (const decl of node.declarations) {
            currentScope.addVariable(decl.name, {
              kind: node.kind,
              init: decl.init,
              isStatic: decl.isStatic,
              line: decl.line,
            });
          }
        }
        break;
      }

      case NodeType.ASSIGNMENT: {
        const existing = currentScope.lookupVariable(node.target);
        if (existing) {
          existing.assignments = existing.assignments || [];
          existing.assignments.push({
            value: node.value,
            isStatic: node.isStatic,
            line: node.line,
          });
          if (!node.isStatic) {
            existing.isStatic = false;
          }
        } else {
          currentScope.addVariable(node.target, {
            kind: 'assignment',
            init: node.value,
            isStatic: node.isStatic,
            line: node.line,
          });
        }
        break;
      }

      case NodeType.IMPORT_DECLARATION: {
        if (Array.isArray(node.importedNames)) {
          for (const name of node.importedNames) {
            currentScope.addImport(name, {
              source: node.source,
              importedName: name,
              line: node.line,
            });
          }
        }
        break;
      }

      case NodeType.TRY_STATEMENT: {
        const tryScope = new Scope(
          ScopeType.TRY_CATCH,
          node.range,
          currentScope,
          'try'
        );
        currentScope.children.push(tryScope);
        break;
      }

      default:
        break;
    }
  }

  /**
   * Find the deepest enclosing scope for a given line number.
   *
   * @param {number} line — 1-indexed line number
   * @returns {Scope}     — Deepest matching scope (defaults to globalScope)
   */
  getScopeAt(line) {
    let current = this.globalScope;

    const findDeepest = (scope) => {
      for (const child of scope.children) {
        if (child.containsLine(line)) {
          current = child;
          findDeepest(child);
          break;
        }
      }
    };

    findDeepest(this.globalScope);
    return current;
  }

  /**
   * Check if a line is within a function scope.
   */
  getEnclosingFunction(line) {
    let scope = this.getScopeAt(line);
    while (scope) {
      if (scope.type === ScopeType.FUNCTION) {
        return scope;
      }
      scope = scope.parent;
    }
    return null;
  }

  /**
   * Check if a line is inside a try/catch block.
   */
  isInTryCatch(line) {
    let scope = this.getScopeAt(line);
    while (scope) {
      if (scope.type === ScopeType.TRY_CATCH) {
        return true;
      }
      scope = scope.parent;
    }
    return false;
  }

  /**
   * Check if a variable at a given line is static (never received user input).
   */
  isVariableStatic(name, line) {
    const scope = this.getScopeAt(line);
    const variable = scope.lookupVariable(name);
    if (!variable) return null;
    return variable.isStatic === true && !variable.isParam;
  }

  /**
   * Check if a variable originated from function parameters or known input.
   */
  isVariableUserInput(name, line) {
    const scope = this.getScopeAt(line);
    const variable = scope.lookupVariable(name);
    if (!variable) return false;
    return variable.isParam === true;
  }
}

export default ScopeTree;
