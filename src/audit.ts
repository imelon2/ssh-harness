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

// Rotate the audit log once it crosses this size, keeping a single `.1` backup,
// so a long-lived session can't grow it unbounded (and ironically trip the
// fail-closed path when the disk fills). Override with SSH_HARNESS_AUDIT_MAX_BYTES.
const DEFAULT_MAX_AUDIT_BYTES = 5 * 1024 * 1024;

function maxAuditBytes(): number {
  const v = Number(process.env.SSH_HARNESS_AUDIT_MAX_BYTES);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_MAX_AUDIT_BYTES;
}

/** Best-effort: if the log exceeds the cap, rename it to `${path}.1` (replacing
 * any prior backup) so the next append starts a fresh file. Never throws. */
function rotateIfOversized(path: string): void {
  try {
    if (fs.statSync(path).size >= maxAuditBytes()) {
      fs.renameSync(path, path + '.1');
    }
  } catch {
    // No file yet, or rotation failed — non-fatal; append proceeds regardless.
  }
}

export function appendAudit(
  path: string,
  event: AuditEvent,
  opts: { bestEffort: boolean },
): void {
  // Ensure parent directory exists with mode 0o700
  fs.mkdirSync(nodePath.dirname(path), { recursive: true, mode: 0o700 });
  rotateIfOversized(path);

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
