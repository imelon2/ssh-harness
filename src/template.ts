import type { RuleDef } from './allowlist.js';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class MissingPlaceholderError extends Error {
  constructor(public readonly key: string) {
    super(`missing placeholder: {${key}}`);
    this.name = 'MissingPlaceholderError';
  }
}

export class UnknownPlaceholderError extends Error {
  constructor(public readonly key: string) {
    super(`unknown placeholder: {${key}}`);
    this.name = 'UnknownPlaceholderError';
  }
}

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

const PLACEHOLDER_RE = /\{(\w+)\}/g;

function substitute(template: string, params: Record<string, unknown>): string {
  return template.replace(PLACEHOLDER_RE, (_match, name: string) => {
    if (!(name in params)) {
      throw new MissingPlaceholderError(name);
    }
    return String(params[name]);
  });
}

export function renderArgv(
  rule: RuleDef,
  params: Record<string, unknown>,
): { host: string; argv: string[] } {
  const host = substitute(rule.template.host, params);
  const argv = rule.template.argv.map((entry) => substitute(entry, params));
  return { host, argv };
}
