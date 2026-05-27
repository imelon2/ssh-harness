#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { buildRegistry, expandWildcardHosts, lintAllowlist, Registry } from './allowlist.js';
import { buildShape } from './schema.js';
import { renderArgv } from './template.js';
import { runSsh, type ExecResult } from './exec.js';
import { appendAudit, redactParams, AuditAppendError, type AuditEvent, type AuditOutcome } from './audit.js';
import { loadHostAliases } from './ssh_config.js';
import { loadConfig, resolveSshConfigPath, type RuntimeConfig } from './config.js';
import { buildTools, type Tool } from './tools.js';
import { buildBuiltinTools, BUILTIN_TOOL_NAME } from './builtin_tools.js';

const VERSION = '0.1.0';

export type CreateServerResult = {
  server: McpServer;
  registry: Registry;
  config: RuntimeConfig;
  tools: Tool[];
};

/**
 * Build (but do not connect) the MCP server. Used by both the CLI entrypoint
 * and the integration tests. Exits the process on fatal startup errors
 * (lint failures, parse failures, host-alias drift under strictLint).
 *
 * For test injection, accept an optional env so tests can override paths.
 */
export function createServer(env: NodeJS.ProcessEnv = process.env): CreateServerResult {
  const baseConfig = loadConfig(env);

  // 1. Load allowlist (exit 2 on parse failure)
  let registry: Registry;
  try {
    registry = buildRegistry(baseConfig.allowlistPath);
  } catch (err) {
    console.error(`[ssh-harness] failed to load allowlist: ${(err as Error).message}`);
    process.exit(2);
  }

  // 1b. Resolve sshConfigPath: env > allowlist hosts.sshConfigRoot > ~/.ssh/config
  const config: RuntimeConfig = {
    ...baseConfig,
    sshConfigPath: resolveSshConfigPath(
      baseConfig.sshConfigEnvOverride,
      baseConfig.allowlistPath,
      registry.sshConfigRoot(),
    ),
  };

  // 2. Lint (exit 3 if errors present)
  const lintResults = lintAllowlist(registry.raw(), { strict: config.strictLint, maxRules: config.maxRules });
  const errors = lintResults.filter(l => l.startsWith('[ERROR]'));
  const warnings = lintResults.filter(l => l.startsWith('[WARN]'));
  if (errors.length > 0) {
    console.error('[ssh-harness] allowlist lint errors:');
    for (const e of errors) console.error('  ' + e);
    process.exit(3);
  }
  for (const w of warnings) console.error('[ssh-harness] ' + w);

  // 3. ssh_config Host cross-check
  let aliases: Set<string>;
  try {
    aliases = loadHostAliases(config.sshConfigPath);
  } catch (err) {
    console.error(`[ssh-harness] could not read ssh_config at ${config.sshConfigPath}: ${(err as Error).message}`);
    if (config.strictLint) process.exit(3);
    aliases = new Set();
  }

  // 3a. Expand allowHosts: ["*"] to the concrete ssh_config Host aliases.
  // Must run before the drift check so the wildcard makes drift a no-op.
  try {
    expandWildcardHosts(registry.raw(), aliases);
  } catch (err) {
    console.error(`[ssh-harness] wildcard expansion failed: ${(err as Error).message}`);
    process.exit(3);
  }

  const driftedHosts = registry.hosts().filter(h => !aliases.has(h.toLowerCase()));
  if (driftedHosts.length > 0) {
    const msg = `[WARN] hosts in allowlist not declared in ssh_config: ${driftedHosts.join(', ')}`;
    console.error('[ssh-harness] ' + msg);
    if (config.strictLint) {
      console.error('[ssh-harness] strict_lint=on, exiting');
      process.exit(3);
    }
  }

  // 4. Reject collisions between rule-derived tool names and built-in tool names
  const collidingRule = registry.list().find((r) => r.tool.name === BUILTIN_TOOL_NAME);
  if (collidingRule !== undefined) {
    console.error(`[ssh-harness] allowlist rule "${collidingRule.id}" uses reserved built-in tool name "${BUILTIN_TOOL_NAME}"`);
    process.exit(3);
  }

  // 5. Build tool catalog (rule-derived + built-in)
  const ruleTools = buildTools(registry, config);
  const builtinTools = buildBuiltinTools(registry, config);
  const tools = [...ruleTools, ...builtinTools];

  // 6. Startup banner (one block, all to stderr so stdout stays clean for MCP transport)
  console.error(`[ssh-harness] cwd=${process.cwd()}`);
  console.error(`[ssh-harness] allowlist=${config.allowlistPath}`);
  console.error(`[ssh-harness] ssh_config=${config.sshConfigPath}`);
  console.error(`[ssh-harness] audit=${config.auditPath}`);
  console.error(`[ssh-harness] audit_mode=${config.auditBestEffort ? 'best-effort' : 'fail-closed'}`);
  console.error(`[ssh-harness] strict_lint=${config.strictLint ? 'on' : 'off'}`);
  console.error(`[ssh-harness] rules=${registry.count()} (cap=${config.maxRules})`);
  console.error(`[ssh-harness] builtin_tools=${builtinTools.length}`);

  // 7. Register everything with the MCP server
  const server = new McpServer(
    { name: 'ssh-harness', version: VERSION },
    { capabilities: { tools: {} } },
  );

  for (const tool of tools) {
    server.registerTool(
      tool.name,
      { description: tool.description, inputSchema: tool.paramsSchema.shape },
      async (args) => tool.handler(args),
    );
  }

  return { server, registry, config, tools };
}

/**
 * The handler pipeline, factored out for unit-testability.
 * Called by every tool handler.
 */
export async function executeRuleCall(
  registry: Registry,
  ruleId: string,
  rawArgs: Record<string, unknown>,
  config: RuntimeConfig,
): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
  const rule = registry.get(ruleId);
  if (!rule) {
    // Should be impossible if SDK routing is sound; defend anyway.
    const ev = baseEvent(ruleId, 'unknown', 'host_denied', rawArgs, [], '', null, 0, '', '', 'unknown rule id');
    safeAppend(config, ev);
    return errorResult(`unknown rule: ${ruleId}`);
  }

  // a. Validate args with Zod (.strict() rejects extras)
  const shape = buildShape(rule.params);
  const parsed = shape.safeParse(rawArgs);
  if (!parsed.success) {
    const ev = baseEvent(rule.id, rule.tool.name, 'schema_error',
      redactParams(rawArgs, rule.params), [], '', null, 0, '', '', parsed.error.message);
    safeAppend(config, ev);
    return errorResult(`schema error: ${parsed.error.message}`);
  }
  const args = parsed.data as Record<string, unknown>;

  // b. Host membership defense-in-depth (in case a string param was not constrained to an enum/pattern matching hosts)
  if ('host' in args) {
    const h = String(args.host);
    if (!registry.hosts().includes(h)) {
      const ev = baseEvent(rule.id, rule.tool.name, 'host_denied',
        redactParams(args, rule.params), [], h, null, 0, '', '', `host '${h}' not in allowlist hosts`);
      safeAppend(config, ev);
      return errorResult(`host not allowed: ${h}`);
    }
  }

  // c. Render argv
  let host: string;
  let argv: string[];
  try {
    ({ host, argv } = renderArgv(rule, args));
  } catch (err) {
    const ev = baseEvent(rule.id, rule.tool.name, 'schema_error',
      redactParams(args, rule.params), [], '', null, 0, '', '', (err as Error).message);
    safeAppend(config, ev);
    return errorResult((err as Error).message);
  }

  // d. Run ssh
  const settings = registry.settings();
  let result: ExecResult;
  try {
    result = await runSsh(host, argv, {
      sshBin: settings.sshBin,
      timeoutMs: settings.timeoutMs,
      maxStdoutBytes: settings.maxStdoutBytes,
      maxStderrBytes: settings.maxStderrBytes,
      configPath: config.sshConfigPath,
      identityFile: settings.identityFile,
    });
  } catch (err) {
    const ev = baseEvent(rule.id, rule.tool.name, 'exec_error',
      redactParams(args, rule.params), redactArgv(argv, rule.params, args), host, null, 0, '', '', (err as Error).message);
    safeAppend(config, ev);
    return errorResult(`exec error: ${(err as Error).message}`);
  }

  // e. Build audit event
  const outcome: AuditOutcome = result.timedOut ? 'timeout' : (result.exitCode === 0 ? 'ok' : 'exec_error');
  const event: AuditEvent = {
    ts: new Date().toISOString(),
    ruleId: rule.id,
    toolName: rule.tool.name,
    outcome,
    params: redactParams(args, rule.params),
    argv: redactArgv(argv, rule.params, args),
    host,
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    stdoutTail: tail(result.stdout, 512),
    stderrTail: tail(result.stderr, 512),
  };

  // f. Append audit (fail-closed semantics)
  try {
    appendAudit(config.auditPath, event, { bestEffort: config.auditBestEffort });
  } catch (err) {
    if (err instanceof AuditAppendError) {
      // Try one best-effort secondary append for forensics, then return MCP error.
      try {
        const failEvent: AuditEvent = { ...event, outcome: 'audit_failed', errorMessage: err.message };
        appendAudit(config.auditPath, failEvent, { bestEffort: true });
      } catch { /* swallow — already in failure path */ }
      return errorResult(`audit append failed (fail-closed): ${err.message}`);
    }
    throw err;
  }

  // g. Return result to MCP client
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        host,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        timedOut: result.timedOut,
        truncated: result.truncated,
        stdout: result.stdout,
        stderr: result.stderr,
      }, null, 2),
    }],
    isError: outcome !== 'ok',
  };
}

// --- helpers ---
function tail(s: string, n: number): string {
  return s.length <= n ? s : s.slice(-n);
}
function redactArgv(argv: string[], specs: Record<string, import('./allowlist.js').ParamSpec>, args: Record<string, unknown>): string[] {
  // Walk argv; replace any token equal to a secret param's value with '[REDACTED]'.
  const secrets = new Set<string>();
  for (const [k, spec] of Object.entries(specs)) {
    if (spec.secret) secrets.add(String(args[k]));
  }
  return argv.map(a => secrets.has(a) ? '[REDACTED]' : a);
}
function errorResult(msg: string) {
  return { content: [{ type: 'text' as const, text: msg }], isError: true };
}
function baseEvent(
  ruleId: string, toolName: string, outcome: AuditOutcome,
  params: Record<string, unknown>, argv: string[], host: string,
  exitCode: number | null, durationMs: number,
  stdoutTail: string, stderrTail: string, errorMessage?: string,
): AuditEvent {
  return {
    ts: new Date().toISOString(),
    ruleId, toolName, outcome, params, argv, host,
    exitCode, durationMs, stdoutTail, stderrTail, errorMessage,
  };
}
function safeAppend(config: RuntimeConfig, event: AuditEvent) {
  try {
    appendAudit(config.auditPath, event, { bestEffort: true });   // schema errors etc. should still try to log
  } catch { /* nothing else to do */ }
}

/**
 * CLI entrypoint. Connects the server to stdio MCP transport.
 */
export async function main(): Promise<void> {
  const { server } = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Trap signals for clean shutdown
  const shutdown = () => {
    server.close().catch(() => {}).finally(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// Run main only when invoked directly (not when imported by tests)
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => {
    console.error('[ssh-harness] fatal:', err);
    process.exit(1);
  });
}
