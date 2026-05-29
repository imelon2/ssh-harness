import { z } from 'zod';
import { type Registry } from './allowlist.js';
import { type RuntimeConfig } from './config.js';
import { type Tool, type ToolResult } from './tools.js';
import { runSsh, type ExecResult } from './exec.js';
import {
  appendAudit,
  AuditAppendError,
  type AuditEvent,
  type AuditOutcome,
} from './audit.js';

export const BUILTIN_RULE_ID = 'builtin:get_allow_host_lists';
export const BUILTIN_TOOL_NAME = 'ssh_harness_get_allow_host_lists';

const HEALTH_CHECK_TIMEOUT_MS = 7000;
const HEALTH_CHECK_SSH_STDOUT_BYTES = 1024;
const HEALTH_CHECK_SSH_BUFFER_BYTES = 1024;
const HEALTH_CHECK_ERROR_TRUNCATE = 256;
// Bound the per-call fan-out: run health checks concurrently but capped, and
// abandon hosts not yet started once the overall deadline passes — otherwise a
// `["*"]`-expanded host list with many down hosts blocks for N × timeout.
const HEALTH_CHECK_CONCURRENCY = 5;
const HEALTH_CHECK_TOTAL_DEADLINE_MS = 30000;

export type HostHealth = {
  host: string;
  reachable: boolean;
  exitCode: number | null;
  durationMs: number;
  timedOut: boolean;
  error?: string;
};

const inputSchema = z.object({
  checkHealth: z.boolean().optional(),
}).strict();

const hostHealthSchema = z.object({
  host: z.string(),
  reachable: z.boolean(),
  exitCode: z.number().int().nullable(),
  durationMs: z.number(),
  timedOut: z.boolean(),
  error: z.string().optional(),
});

/** Structured output. `results`/`summary`/`partial` present only when checkHealth ran. */
const outputShape: z.ZodRawShape = {
  hosts: z.array(z.string()),
  sshConfigPath: z.string(),
  checked: z.boolean(),
  results: z.array(hostHealthSchema).optional(),
  summary: z.object({ total: z.number(), reachable: z.number(), unreachable: z.number() }).optional(),
  partial: z.boolean().optional(),
};

export function buildBuiltinTools(registry: Registry, config: RuntimeConfig): Tool[] {
  const tool: Tool = {
    name: BUILTIN_TOOL_NAME,
    description:
      'Return the list of SSH host aliases this MCP is allowed to reach (sourced from allowlist.yaml hosts.allowHosts).\n' +
      'Read-only. Optional input { checkHealth?: boolean }: when true, opens one short SSH connection (`ssh ... -- true`, ConnectTimeout=5s) per host to verify reachability.\n' +
      'Use when: discovering which hosts the MCP can target before invoking host-specific tools, or verifying connectivity before a maintenance check.',
    paramsSchema: inputSchema as unknown as z.ZodObject<Record<string, z.ZodTypeAny>>,
    outputSchema: outputShape,
    annotations: { title: BUILTIN_TOOL_NAME, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    handler: async (args: unknown) => executeBuiltinCall(registry, config, args),
  };
  return [tool];
}

export async function executeBuiltinCall(
  registry: Registry,
  config: RuntimeConfig,
  rawArgs: unknown,
): Promise<ToolResult> {
  const parsed = inputSchema.safeParse(rawArgs ?? {});
  if (!parsed.success) {
    const event = makeEvent('schema_error', { input: redactUnknown(rawArgs) }, ['__builtin__', 'list'], '', null, 0, '', parsed.error.message, parsed.error.message);
    safeAudit(config, event);
    return errorResult(`schema error: ${parsed.error.message}`);
  }

  const checkHealth = parsed.data.checkHealth === true;
  const hosts = registry.hosts();

  if (!checkHealth) {
    const body = {
      hosts,
      sshConfigPath: config.sshConfigPath,
      checked: false as const,
    };
    const event = makeEvent('ok', { checkHealth: false }, ['__builtin__', 'list'], '', 0, 0, `${hosts.length} hosts listed`, '');
    try {
      appendAudit(config.auditPath, event, { bestEffort: config.auditBestEffort });
    } catch (err) {
      if (err instanceof AuditAppendError) {
        secondaryAudit(config, event, err.message);
        return errorResult(`audit append failed (fail-closed): ${err.message}`);
      }
      throw err;
    }
    return okResult(body, false);
  }

  // checkHealth === true: probe hosts with bounded concurrency under an overall
  // deadline. Hosts not started before the deadline are reported as skipped, so
  // the call returns in bounded time regardless of host count.
  const settings = registry.settings();
  const t0 = Date.now();
  const deadline = t0 + HEALTH_CHECK_TOTAL_DEADLINE_MS;
  const results: HostHealth[] = new Array(hosts.length);
  let partial = false;
  let next = 0;

  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= hosts.length) return;
      const host = hosts[i];

      if (Date.now() >= deadline) {
        results[i] = { host, reachable: false, exitCode: null, durationMs: 0, timedOut: false,
          error: 'skipped: health-check deadline reached' };
        partial = true;
        continue;
      }

      const startedAt = Date.now();
      let execResult: ExecResult | undefined;
      let thrownError: string | undefined;
      try {
        execResult = await runSsh(host, ['true'], {
          sshBin: settings.sshBin,
          timeoutMs: HEALTH_CHECK_TIMEOUT_MS,
          maxStdoutBytes: HEALTH_CHECK_SSH_STDOUT_BYTES,
          maxStderrBytes: HEALTH_CHECK_SSH_BUFFER_BYTES,
          configPath: config.sshConfigPath,
          identityFile: settings.identityFile,
        });
      } catch (err) {
        thrownError = err instanceof Error ? err.message : String(err);
      }

      if (thrownError !== undefined || execResult === undefined) {
        const msg = thrownError ?? 'exec returned no result';
        results[i] = { host, reachable: false, exitCode: null, durationMs: Date.now() - startedAt,
          timedOut: false, error: truncate(msg, HEALTH_CHECK_ERROR_TRUNCATE) };
        continue;
      }

      const reachable = execResult.exitCode === 0 && !execResult.timedOut;
      const entry: HostHealth = {
        host,
        reachable,
        exitCode: execResult.exitCode,
        durationMs: Math.round(execResult.durationMs),
        timedOut: execResult.timedOut,
      };
      if (!reachable) {
        const tail = execResult.stderr.trim() || (execResult.timedOut ? 'timed out' : 'ssh failed');
        entry.error = truncate(tail, HEALTH_CHECK_ERROR_TRUNCATE);
      }
      results[i] = entry;
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(HEALTH_CHECK_CONCURRENCY, hosts.length) }, () => worker()),
  );

  const firstError = results.find((r) => r.error)?.error ?? '';
  const reachableCount = results.filter((r) => r.reachable).length;
  const unreachableCount = results.length - reachableCount;
  const summary = { total: results.length, reachable: reachableCount, unreachable: unreachableCount };
  const body = {
    hosts,
    sshConfigPath: config.sshConfigPath,
    checked: true as const,
    results,
    summary,
    ...(partial ? { partial: true } : {}),
  };
  const totalDuration = Date.now() - t0;
  const event = makeEvent(
    unreachableCount === 0 ? 'ok' : 'exec_error',
    { checkHealth: true },
    ['__builtin__', 'check'],
    '',
    unreachableCount === 0 ? 0 : 1,
    totalDuration,
    `${reachableCount}/${results.length} reachable`,
    truncate(firstError, HEALTH_CHECK_ERROR_TRUNCATE),
  );
  try {
    appendAudit(config.auditPath, event, { bestEffort: config.auditBestEffort });
  } catch (err) {
    if (err instanceof AuditAppendError) {
      secondaryAudit(config, event, err.message);
      return errorResult(`audit append failed (fail-closed): ${err.message}`);
    }
    throw err;
  }

  return okResult(body, unreachableCount > 0);
}

// --- helpers ---

function makeEvent(
  outcome: AuditOutcome,
  params: Record<string, unknown>,
  argv: string[],
  host: string,
  exitCode: number | null,
  durationMs: number,
  stdoutTail: string,
  stderrTail: string,
  errorMessage?: string,
): AuditEvent {
  return {
    ts: new Date().toISOString(),
    ruleId: BUILTIN_RULE_ID,
    toolName: BUILTIN_TOOL_NAME,
    outcome,
    params,
    argv,
    host,
    exitCode,
    durationMs,
    stdoutTail,
    stderrTail,
    errorMessage,
  };
}

function secondaryAudit(config: RuntimeConfig, event: AuditEvent, message: string): void {
  try {
    const failEvent: AuditEvent = { ...event, outcome: 'audit_failed', errorMessage: message };
    appendAudit(config.auditPath, failEvent, { bestEffort: true });
  } catch {
    // already in failure path
  }
}

function safeAudit(config: RuntimeConfig, event: AuditEvent): void {
  try {
    appendAudit(config.auditPath, event, { bestEffort: true });
  } catch {
    // schema errors must not block the response; best-effort only
  }
}

function okResult(
  body: Record<string, unknown>,
  isError: boolean,
): ToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(body, null, 2) }],
    structuredContent: body,
    isError,
  };
}

function errorResult(msg: string): ToolResult {
  return { content: [{ type: 'text' as const, text: msg }], isError: true };
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 3) + '...';
}

function redactUnknown(v: unknown): unknown {
  if (v === null || v === undefined) return v;
  if (typeof v !== 'object') return v;
  try {
    return JSON.parse(JSON.stringify(v));
  } catch {
    return '[unserializable]';
  }
}
