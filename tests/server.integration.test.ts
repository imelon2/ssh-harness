import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'node:os';
import * as path from 'node:path';
import fc from 'fast-check';
import * as cp from 'node:child_process';
import { EventEmitter } from 'node:events';

vi.mock('node:child_process');
vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>();
  return { ...actual };
});
const mockSpawn = vi.mocked(cp.spawn);

function fakeProc(opts: {
  stdoutChunks?: Buffer[];
  stderrChunks?: Buffer[];
  exitCode?: number | null;
}): cp.ChildProcess {
  const proc = new EventEmitter() as cp.ChildProcess & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    killed: boolean;
    kill: (sig?: NodeJS.Signals | number) => boolean;
  };
  proc.stdout = new EventEmitter() as cp.ChildProcess['stdout'] as never;
  proc.stderr = new EventEmitter() as cp.ChildProcess['stderr'] as never;
  proc.killed = false;
  proc.kill = () => { proc.killed = true; return true; };
  setImmediate(() => {
    for (const c of opts.stdoutChunks ?? []) (proc.stdout as EventEmitter).emit('data', c);
    for (const c of opts.stderrChunks ?? []) (proc.stderr as EventEmitter).emit('data', c);
    (proc as EventEmitter).emit('close', opts.exitCode ?? 0, null);
  });
  return proc;
}

import { executeRuleCall, createServer } from '../src/server.js';
import { buildRegistry } from '../src/allowlist.js';
import { renderArgv } from '../src/template.js';
import type { RuntimeConfig } from '../src/config.js';

describe('ssh-harness server integration', () => {
  let tmp: string;
  let allowlistPath: string;
  let auditPath: string;
  let sshConfigPath: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-harness-integ-'));
    const dir = path.join(tmp, '.ssh_harness');
    fs.mkdirSync(dir, { recursive: true });
    allowlistPath = path.join(dir, 'allowlist.yaml');
    auditPath = path.join(dir, 'audit.log');
    sshConfigPath = path.join(dir, 'ssh_config');
    fs.writeFileSync(sshConfigPath, 'Host localhost\n  HostName 127.0.0.1\n');
    mockSpawn.mockImplementation(() => fakeProc({
      stdoutChunks: [Buffer.from('ok\n')],
      exitCode: 0,
    }));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
    mockSpawn.mockReset();
  });

  function setupRule(rules: string) {
    const yaml = `
version: 2
hosts:
  allowHosts: &hosts [localhost]
rules:
${rules}
`;
    fs.writeFileSync(allowlistPath, yaml);
    return buildRegistry(allowlistPath);
  }

  function makeConfig(overrides: Partial<RuntimeConfig> = {}): RuntimeConfig {
    return {
      allowlistPath, auditPath, sshConfigPath,
      auditBestEffort: false, strictLint: true, maxRules: 40,
      ...overrides,
    };
  }

  it('rejects unknown tool names with no spawn', async () => {
    const registry = setupRule(`
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [uptime] }
`);
    const result = await executeRuleCall(registry, 'does_not_exist', { host: 'localhost' }, makeConfig());
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/unknown rule/i);
    expect(mockSpawn).not.toHaveBeenCalled();
  });

  it('strips extra/unknown params (.strict())', async () => {
    const registry = setupRule(`
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [uptime] }
`);
    const result = await executeRuleCall(registry, 'r1', { host: 'localhost', extra: 'param' }, makeConfig());
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/schema error/i);
    expect(mockSpawn).not.toHaveBeenCalled();
  });

  it('rejects schema-valid but adversarial integer (C-1)', async () => {
    const registry = setupRule(`
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params:
      host: { type: string, enum: *hosts }
      lines: { type: integer, maximum: 1000 }
    template: { host: "{host}", argv: [tail, "-n", "{lines}", "/var/log/foo"] }
`);
    const result = await executeRuleCall(registry, 'r1', { host: 'localhost', lines: 999999999 }, makeConfig());
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/schema error/i);
    expect(mockSpawn).not.toHaveBeenCalled();
  });

  it('renders adversarial param values as literal argv (fast-check property)', () => {
    const rule = {
      id: 'r1',
      tool: { name: 'ssh_r1', description: 'r1' },
      params: {},
      template: { host: '{host}', argv: ['echo', '{msg}'] },
    } as never;

    const adversarial = fc.oneof(
      fc.string(),
      fc.constantFrom('; rm -rf /', '$(rm -rf /)', '`reboot`', '| cat /etc/passwd', '&& shutdown', '\n\r', '\x00\x01'),
      fc.unicodeString({ minLength: 0, maxLength: 1024 }),
    );

    fc.assert(
      fc.property(adversarial, (msg) => {
        const { argv } = renderArgv(rule, { host: 'localhost', msg });
        expect(argv.length).toBe(2);
        expect(argv[0]).toBe('echo');
        expect(argv[1]).toBe(msg);
      }),
      { numRuns: 1000 },
    );
  });

  it('warns when allowlist.hosts has no matching Host alias in ssh_config', () => {
    fs.writeFileSync(sshConfigPath, 'Host other-host\n  HostName 10.0.0.1\n');
    const yaml = `
version: 2
hosts:
  allowHosts: &hosts [localhost]
rules:
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [uptime] }
`;
    fs.writeFileSync(allowlistPath, yaml);

    const env = { ...process.env, SSH_HARNESS_ALLOWLIST: allowlistPath, SSH_HARNESS_CONFIG: sshConfigPath,
      SSH_HARNESS_AUDIT: auditPath, SSH_HARNESS_STRICT_LINT: '0' };

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      createServer(env);
      const stderrCalls = stderrSpy.mock.calls.map(c => String(c[0])).join('');
      const consoleCalls = consoleErrorSpy.mock.calls.map(c => c.map(String).join(' ')).join('\n');
      const allOutput = stderrCalls + '\n' + consoleCalls;
      expect(allOutput).toMatch(/not declared in ssh_config|hosts.*localhost/i);
    } finally {
      stderrSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    }
  });

  it('redacts secret param values even when embedded in an argv token', async () => {
    const registry = setupRule(`
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params:
      host: { type: string, enum: *hosts }
      token: { type: string, pattern: "[A-Za-z0-9]+", secret: true }
    template: { host: "{host}", argv: [echo, "--token={token}"] }
`);
    const result = await executeRuleCall(registry, 'r1', { host: 'localhost', token: 'SECRETvalue123' }, makeConfig());
    expect(result.isError).toBeFalsy();

    const log = fs.readFileSync(auditPath, 'utf8');
    expect(log).not.toContain('SECRETvalue123');   // not whole-token, so equality redaction would have leaked it
    expect(log).toContain('[REDACTED]');
  });

  it('redacts secret values echoed back in stdout (audit log + client result)', async () => {
    const registry = setupRule(`
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params:
      host: { type: string, enum: *hosts }
      token: { type: string, pattern: "[A-Za-z0-9]+", secret: true }
    template: { host: "{host}", argv: [echo, "{token}"] }
`);
    mockSpawn.mockImplementation(() => fakeProc({
      stdoutChunks: [Buffer.from('server replied: SUPERSECRET42 (denied)\n')],
      exitCode: 0,
    }));

    const result = await executeRuleCall(registry, 'r1', { host: 'localhost', token: 'SUPERSECRET42' }, makeConfig());
    expect(result.content[0].text).not.toContain('SUPERSECRET42');
    expect(String(result.structuredContent?.stdout)).not.toContain('SUPERSECRET42');

    const log = fs.readFileSync(auditPath, 'utf8');
    expect(log).not.toContain('SUPERSECRET42');
    expect(log).toContain('[REDACTED]');
  });

  it('fails the call when audit append fails (fail-closed)', async () => {
    const registry = setupRule(`
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [uptime] }
`);

    const spy = vi.spyOn(fs, 'appendFileSync').mockImplementation(() => {
      throw new Error('EIO disk failure');
    });

    try {
      const result = await executeRuleCall(registry, 'r1', { host: 'localhost' }, makeConfig({ auditBestEffort: false }));
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toMatch(/audit append failed/i);
    } finally {
      spy.mockRestore();
    }
  });
});
