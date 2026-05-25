import * as fs from 'fs';
import * as nodePath from 'path';
import type { ParamSpec } from './allowlist.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuditOutcome =
  | 'ok'
  | 'schema_error'
  | 'host_denied'
  | 'exec_error'
  | 'timeout'
  | 'audit_failed';

export type AuditEvent = {
  ts: string;                          // ISO 8601 with ms
  ruleId: string;
  toolName: string;
  outcome: AuditOutcome;
  params: Record<string, unknown>;     // post-redaction
  argv: string[];                      // post-redaction
  host: string;
  exitCode: number | null;
  durationMs: number;
  stdoutTail: string;                  // last 512 bytes, codepoint-safe
  stderrTail: string;
  errorMessage?: string;
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class AuditAppendError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'AuditAppendError';
  }
}

// ---------------------------------------------------------------------------
// appendAudit
// ---------------------------------------------------------------------------

export function appendAudit(
  path: string,
  event: AuditEvent,
  opts: { bestEffort: boolean },
): void {
  // Ensure parent directory exists with mode 0o700
  fs.mkdirSync(nodePath.dirname(path), { recursive: true, mode: 0o700 });

  const line = JSON.stringify(event) + '\n';

  try {
    fs.appendFileSync(path, line, { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    if (opts.bestEffort === true) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[audit] append failed: ${msg}\n`);
      return;
    }
    throw new AuditAppendError('audit append failed', err);
  }
}

// ---------------------------------------------------------------------------
// redactParams
// ---------------------------------------------------------------------------

export function redactParams(
  params: Record<string, unknown>,
  specs: Record<string, ParamSpec>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(params)) {
    if (specs[key]?.secret === true) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = params[key];
    }
  }
  return result;
}
