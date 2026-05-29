#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { buildRegistry, emptyRegistry, expandWildcardHosts, lintAllowlist, Registry } from './allowlist.js';
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
 * The read-only default allowlist dropped in when none exists yet. Mirrors the
 * SessionStart hook's seed (hook/init-ssh-harness.sh) so a fresh install has
 * working diagnostics without depending on the hook having run. `["*"]` expands
 * to the Host aliases in the resolved ssh_config; commands are read-only.
 */
const DEFAULT_ALLOWLIST_YAML = `# Local allowlist. Edits gated by CODEOWNERS.
# Schema: docs/allowlist-guide.md, README.md
version: 2

hosts:
  allowHosts: &hosts ["*"]                     # ["*"] -> expand to every Host alias in ssh_config (excluding \`Host *\` wildcard).

settings:
  timeoutMs: 30000
  maxStdoutBytes: 262144
  maxStderrBytes: 65536

rules:
  - id: get_uptime
    tool:
      name: ssh_harness_get_uptime
      description: |
        Return how long the host has been up and the current load averages (runs \`uptime\`).
        Read-only, no arguments. One-shot snapshot.
    params:
      host:
        type: string
        enum: *hosts
        description: Target host alias from the ssh_config above
    template:
      host: "{host}"
      argv: [uptime]

  - id: get_disk_usage
    tool:
      name: ssh_harness_get_disk_usage
      description: |
        Show filesystem disk usage in human-readable form (runs \`df -h\`).
        Read-only, no arguments. One-shot snapshot.
    params:
      host:
        type: string
        enum: *hosts
    template:
      host: "{host}"
      argv: [df, -h]

  - id: get_process_top
    tool:
      name: ssh_harness_get_process_top
      description: |
        Snapshot all running processes with CPU/memory usage in forest form (runs \`ps auxf\`).
        Read-only, no arguments. One-shot snapshot.
    params:
      host:
        type: string
        enum: *hosts
    template:
      host: "{host}"
      argv: [ps, auxf]
`;

/**
 * Best-effort: seed the read-only default allowlist if none exists. Never
 * throws — a read-only filesystem or a race just falls through to the loader,
 * which degrades gracefully. Skipped when an explicit path override is given
 * via SSH_HARNESS_ALLOWLIST (tests and operators manage their own file).
 */
function ensureAllowlistSeeded(allowlistPath: string, env: NodeJS.ProcessEnv): void {
  if (env.SSH_HARNESS_ALLOWLIST) return;
  try {
    if (fs.existsSync(allowlistPath)) return;
    fs.mkdirSync(path.dirname(allowlistPath), { recursive: true });
    fs.writeFileSync(allowlistPath, DEFAULT_ALLOWLIST_YAML, { flag: 'wx' });
    console.error(`[ssh-harness] seeded default allowlist at ${allowlistPath}`);
  } catch (err) {
    console.error(`[ssh-harness] could not seed default allowlist: ${(err as Error).message}`);
  }
}

/**
 * Build (but do not connect) the MCP server. Used by both the CLI entrypoint
 * and the integration tests.
 *
 * Startup is fail-OPEN for the protocol but fail-CLOSED for tool exposure: a
 * missing or invalid allowlist NEVER calls process.exit() (exiting before the
 * transport connects surfaces to the client as an opaque -32000). Instead the
 * server starts with ZERO rule tools — the read-only builtin tool stays
 * available, the handshake succeeds, and the configuration error is logged.
 *
 * For test injection, accept an optional env so tests can override paths.
 */
export function createServer(env: NodeJS.ProcessEnv = process.env): CreateServerResult {
  const baseConfig = loadConfig(env);
  ensureAllowlistSeeded(baseConfig.allowlistPath, env);

  // Load + validate the allowlist. Any failure degrades to an empty registry
  // (no rule tools) rather than killing the process before the handshake.
  let registry: Registry = emptyRegistry();
  let config: RuntimeConfig = { ...baseConfig };
  try {
    registry = buildRegistry(baseConfig.allowlistPath);

    // Resolve sshConfigPath: env > allowlist hosts.sshConfigRoot > ~/.ssh/config
    config = {
      ...baseConfig,
      sshConfigPath: resolveSshConfigPath(
        baseConfig.sshConfigEnvOverride,
        baseConfig.allowlistPath,
        registry.sshConfigRoot(),
      ),
    };

    // Lint (throw on errors; warnings are logged and tolerated)
    const lintResults = lintAllowlist(registry.raw(), { strict: config.strictLint, maxRules: config.maxRules });
    const errors = lintResults.filter(l => l.startsWith('[ERROR]'));
    const warnings = lintResults.filter(l => l.startsWith('[WARN]'));
    for (const w of warnings) console.error('[ssh-harness] ' + w);
    if (errors.length > 0) {
      throw new Error('allowlist lint errors:\n  ' + errors.join('\n  '));
    }

    // ssh_config Host cross-check
    let aliases: Set<string>;
    try {
      aliases = loadHostAliases(config.sshConfigPath);
    } catch (err) {
      if (config.strictLint) {
        throw new Error(`could not read ssh_config at ${config.sshConfigPath}: ${(err as Error).message}`);
      }
      console.error(`[ssh-harness] could not read ssh_config at ${config.sshConfigPath}: ${(err as Error).message}`);
      aliases = new Set();
    }

    // Expand allowHosts: ["*"] to the concrete ssh_config Host aliases.
    // Must run before the drift check so the wildcard makes drift a no-op.
    expandWildcardHosts(registry.raw(), aliases);

    const driftedHosts = registry.hosts().filter(h => !aliases.has(h.toLowerCase()));
    if (driftedHosts.length > 0) {
      const msg = `hosts in allowlist not declared in ssh_config: ${driftedHosts.join(', ')}`;
      if (config.strictLint) {
        throw new Error(msg + ' (strict_lint=on)');
      }
      console.error(`[ssh-harness] [WARN] ${msg}`);
    }

    // Reject collisions between rule-derived tool names and the built-in tool name
    const collidingRule = registry.list().find((r) => r.tool.name === BUILTIN_TOOL_NAME);
    if (collidingRule !== undefined) {
      throw new Error(`allowlist rule "${collidingRule.id}" uses reserved built-in tool name "${BUILTIN_TOOL_NAME}"`);
    }
  } catch (err) {
    console.error(`[ssh-harness] allowlist disabled — starting with no rule tools: ${(err as Error).message}`);
    console.error('[ssh-harness] fix .ssh_harness/allowlist.yaml and reload to enable rule tools.');
    registry = emptyRegistry();
    config = { ...baseConfig };
  }

  // Build tool catalog (rule-derived + built-in). Builtin tool is always present.
  const ruleTools = registry.count() > 0 ? buildTools(registry, config) : [];
  const builtinTools = buildBuiltinTools(registry, config);
  const tools = [...ruleTools, ...builtinTools];

  // Startup banner (all to stderr so stdout stays clean for MCP transport)
  console.error(`[ssh-harness] cwd=${process.cwd()}`);
  console.error(`[ssh-harness] allowlist=${config.allowlistPath}`);
  console.error(`[ssh-harness] ssh_config=${config.sshConfigPath}`);
  console.error(`[ssh-harness] audit=${config.auditPath}`);
  console.error(`[ssh-harness] audit_mode=${config.auditBestEffort ? 'best-effort' : 'fail-closed'}`);
  console.error(`[ssh-harness] strict_lint=${config.strictLint ? 'on' : 'off'}`);
  console.error(`[ssh-harness] rules=${registry.count()} (cap=${config.maxRules})`);
  console.error(`[ssh-harness] builtin_tools=${builtinTools.length}`);

  // Register everything with the MCP server
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
