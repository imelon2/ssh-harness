// Build the distributable MCP server bundle.
//
// The plugin is distributed via git (no npm install on the user side), so the
// runtime artifact must be self-contained. We bundle src/server.ts and all of
// its dependencies (@modelcontextprotocol/sdk, yaml, zod) into a single ESM
// file at bridge/server.js with zero external imports.
//
// The createRequire banner is required because some deps (e.g. `yaml`) are CJS
// and call require() internally; esbuild's ESM output otherwise throws
// "Dynamic require of X is not supported" at runtime.

import { build } from 'esbuild';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);

// Type-check only; the bundle below is the sole emitted artifact.
execSync('tsc --noEmit', { stdio: 'inherit' });

await build({
  entryPoints: ['src/server.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  outfile: 'bridge/server.js',
  banner: {
    js: "import { createRequire as __createRequire } from 'module'; const require = __createRequire(import.meta.url);",
  },
});

console.log('[build] bundled -> bridge/server.js');
