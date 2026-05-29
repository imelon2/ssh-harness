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
});
