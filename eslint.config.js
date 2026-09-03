import eslint from '@eslint/js';

export default [
  {
    ignores: ['coverage/', 'node_modules/']
  },
  eslint.configs.recommended,
  {
    files: ['**/*.{js,mjs}'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly'
      }
    },
    rules: {
      'no-console': ['error', { allow: ['log', 'error'] }],
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
    }
  }
];
