import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createServer } from '../src/server.js';

describe('createServer', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-harness-server-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  function writeAllowlist(yaml: string) {
    const dir = path.join(tmp, '.ssh_harness');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'allowlist.yaml'), yaml);
    fs.writeFileSync(path.join(dir, 'ssh_config'), 'Host localhost\n  HostName 127.0.0.1\n');
    return dir;
  }

  it('registers exactly N tools from a N-rule allowlist', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: &hosts [localhost]
rules:
  - id: r1
    tool: { name: ssh_r1, description: "r1" }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [uptime] }
  - id: r2
    tool: { name: ssh_r2, description: "r2" }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [whoami] }
`;
    writeAllowlist(yaml);

    const env = { ...process.env, SSH_HARNESS_ALLOWLIST: path.join(tmp, '.ssh_harness', 'allowlist.yaml'),
      SSH_HARNESS_CONFIG: path.join(tmp, '.ssh_harness', 'ssh_config'),
      SSH_HARNESS_AUDIT: path.join(tmp, '.ssh_harness', 'audit.log'),
    };

    const { registry, tools } = createServer(env);
    expect(registry.count()).toBe(2);
    expect(tools.length).toBe(registry.count() + 1);
    expect(tools.map((t) => t.name)).toContain('ssh_harness_get_allow_host_lists');
  });

  // Regression: a missing allowlist must NOT exit the process before the MCP
  // transport connects (that surfaces to the client as an opaque -32000).
  // The server degrades to zero rule tools but keeps the read-only builtin.
  it('degrades to builtin-only (no exit) when the allowlist is missing', () => {
    const env = { ...process.env,
      SSH_HARNESS_ALLOWLIST: path.join(tmp, 'does-not-exist', 'allowlist.yaml'),
      SSH_HARNESS_AUDIT: path.join(tmp, 'audit.log'),
    };

    const { registry, tools } = createServer(env);
    expect(registry.count()).toBe(0);
    expect(tools.map((t) => t.name)).toEqual(['ssh_harness_get_allow_host_lists']);
  });

  // Security: the auto-seed default must expose NO hosts / NO rule tools — the
  // operator opts in, rather than the LLM silently gaining access to every host
  // in ssh_config on first run.
  it('auto-seeds a SAFE empty allowlist by default (no hosts, no rule tools)', () => {
    const env = { ...process.env, CLAUDE_PROJECT_DIR: tmp };
    delete (env as Record<string, string | undefined>).SSH_HARNESS_ALLOWLIST;
    delete (env as Record<string, string | undefined>).SSH_HARNESS_SEED_WILDCARD;

    const { registry, tools } = createServer(env);
    expect(registry.hosts()).toEqual([]);
    expect(registry.count()).toBe(0);
    expect(tools.map((t) => t.name)).toEqual(['ssh_harness_get_allow_host_lists']);

    const seeded = fs.readFileSync(path.join(tmp, '.ssh_harness', 'allowlist.yaml'), 'utf8');
    expect(seeded).toMatch(/allowHosts:\s*\[\]/);
    expect(seeded).toMatch(/rules:\s*\[\]/);
  });

  // Rule tools advertise read-only behavior via MCP annotations + structured output.
  it('seeds wildcard tools with read-only annotations and an output schema when opted in', () => {
    const sshConfig = path.join(tmp, 'ssh_config');
    fs.writeFileSync(sshConfig, 'Host h1\n  HostName 127.0.0.1\n');
    const env = { ...process.env, CLAUDE_PROJECT_DIR: tmp, SSH_HARNESS_SEED_WILDCARD: '1', SSH_HARNESS_CONFIG: sshConfig };
    delete (env as Record<string, string | undefined>).SSH_HARNESS_ALLOWLIST;

    const { tools } = createServer(env);
    const rule = tools.find((t) => t.name === 'ssh_harness_get_uptime');
    expect(rule).toBeDefined();
    expect(rule!.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, openWorldHint: true });
    expect(rule!.outputSchema).toBeDefined();
  });
});
