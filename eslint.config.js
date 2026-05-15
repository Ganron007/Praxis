/**
 * ESLint flat config — covers `cli/**\/*.js`.
 *
 * Conservative rules for now: error on undeclared globals and unused
 * imports, warn on most stylistic issues. Tighten over time.
 */

import js from '@eslint/js';
import globals from 'globals';

export default [
  js.configs.recommended,
  {
    files: ['cli/**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        ...globals.node,
        fetch: 'readonly',
        Response: 'readonly',
        Request: 'readonly',
        Headers: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-empty': ['warn', { allowEmptyCatch: true }],
      'no-constant-condition': ['warn', { checkLoops: false }],
      'no-prototype-builtins': 'off',
      'no-useless-escape': 'warn',
    },
  },
  {
    files: ['cli/__tests__/**/*.js', 'cli/__tests__/**/*.test.js'],
    languageOptions: {
      globals: {
        ...globals.node,
        fetch: 'readonly',
        Response: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': 'off',
    },
  },
  {
    ignores: ['node_modules/', 'cli/data/', 'configs/', 'checklists/', 'snippets/', 'ai-defense/'],
  },
];
