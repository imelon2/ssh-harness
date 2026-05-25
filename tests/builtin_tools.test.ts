import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cp from 'node:child_process';

vi.mock('node:child_process');
vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>();
  return { ...actual };
});
const mockSpawnSync = vi.mocked(cp.spawnSync);

import {
  buildBuiltinTools,
  executeBuiltinCall,
  BUILTIN_TOOL_NAME,
  BUILTIN_RULE_ID,
} from '../src/builtin_tools.js';
import { buildRegistry } from '../src/allowlist.js';
import type { RuntimeConfig } from '../src/config.js';

describe('builtin_tools: ssh_harness_get_allow_host_lists', () => {
  let tmp: string;
  let allowlistPath: string;
  let auditPath: string;
  let sshConfigPath: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-harness-builtin-'));
    const dir = path.join(tmp, '.ssh_harness');
    fs.mkdirSync(dir, { recursive: true });
    allowlistPath = path.join(dir, 'allowlist.yaml');
    auditPath = path.join(dir, 'audit.log');
    sshConfigPath = path.join(dir, 'ssh_config');
    fs.writeFileSync(sshConfigPath, 'Host alpha\n  HostName 10.0.0.1\nHost beta\n  HostName 10.0.0.2\n');
    const yaml = `
version: 2
hosts:
  allowHosts: &hosts [alpha, beta]
rules:
  - id: r1
    tool: { name: ssh_r1, description: r1 }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [uptime] }
`;
    fs.writeFileSync(allowlistPath, yaml);
    mockSpawnSync.mockReset();
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
    mockSpawnSync.mockReset();
  });

  function makeConfig(overrides: Partial<RuntimeConfig> = {}): RuntimeConfig {
    return {
      allowlistPath,
      auditPath,
      sshConfigPath,
      auditBestEffort: false,
      strictLint: true,
      maxRules: 40,
      ...overrides,
    };
  }

  function mockHostExitStatus(statusByHost: Record<string, number>) {
    mockSpawnSync.mockImplementation((_bin: unknown, argvUnknown: unknown) => {
      const argv = Array.isArray(argvUnknown) ? (argvUnknown as string[]) : [];
      const host = argv.find((a) => statusByHost[a] !== undefined) ?? '';
      const status = statusByHost[host] ?? 1;
      return {
        status,
        stdout: Buffer.from(''),
        stderr: status === 0 ? Buffer.from('') : Buffer.from('connection refused'),
        signal: null,
        pid: 1234,
        output: [],
      } as unknown as ReturnType<typeof cp.spawnSync>;
    });
  }

  it('factory returns exactly one tool with the expected name', () => {
    const registry = buildRegistry(allowlistPath);
    const tools = buildBuiltinTools(registry, makeConfig());
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe(BUILTIN_TOOL_NAME);
    expect(tools[0].description.toLowerCase()).toContain('use when');
  });

  it('list-only path returns hosts and checked:false; no spawn occurs', async () => {
    const registry = buildRegistry(allowlistPath);
    const config = makeConfig();
    const result = await executeBuiltinCall(registry, config, {});
    expect(result.isError).toBeFalsy();
    const body = JSON.parse(result.content[0].text);
    expect(body).toEqual({
      hosts: ['alpha', 'beta'],
      sshConfigPath,
      checked: false,
    });
    expect(mockSpawnSync).not.toHaveBeenCalled();
  });

  it('list-only path also accepts { checkHealth: false }', async () => {
    const registry = buildRegistry(allowlistPath);
    const result = await executeBuiltinCall(registry, makeConfig(), { checkHealth: false });
    expect(result.isError).toBeFalsy();
    const body = JSON.parse(result.content[0].text);
    expect(body.checked).toBe(false);
    expect(mockSpawnSync).not.toHaveBeenCalled();
  });

  it('check path reports reachable:true when ssh exit status is 0', async () => {
    mockHostExitStatus({ alpha: 0, beta: 0 });
    const registry = buildRegistry(allowlistPath);
    const result = await executeBuiltinCall(registry, makeConfig(), { checkHealth: true });
    expect(result.isError).toBeFalsy();
    const body = JSON.parse(result.content[0].text);
    expect(body.checked).toBe(true);
    expect(body.results).toHaveLength(2);
    expect(body.results.every((r: { reachable: boolean }) => r.reachable)).toBe(true);
    expect(body.summary).toEqual({ total: 2, reachable: 2, unreachable: 0 });
    expect(mockSpawnSync).toHaveBeenCalledTimes(2);
  });

  it('check path reports reachable:false when ssh exit status is non-zero', async () => {
    mockHostExitStatus({ alpha: 0, beta: 255 });
    const registry = buildRegistry(allowlistPath);
    const result = await executeBuiltinCall(registry, makeConfig(), { checkHealth: true });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    const alpha = body.results.find((r: { host: string }) => r.host === 'alpha');
    const beta = body.results.find((r: { host: string }) => r.host === 'beta');
    expect(alpha.reachable).toBe(true);
    expect(beta.reachable).toBe(false);
    expect(beta.exitCode).toBe(255);
    expect(beta.error).toMatch(/connection refused/);
    expect(body.summary).toEqual({ total: 2, reachable: 1, unreachable: 1 });
  });

  it('check path isolates a thrown runSsh error to one host', async () => {
    let callIndex = 0;
    mockSpawnSync.mockImplementation(() => {
      callIndex++;
      if (callIndex === 1) {
        throw new Error('spawn fail for first host');
      }
      return {
        status: 0,
        stdout: Buffer.from(''),
        stderr: Buffer.from(''),
        signal: null,
        pid: 4242,
        output: [],
      } as unknown as ReturnType<typeof cp.spawnSync>;
    });
    const registry = buildRegistry(allowlistPath);
    const result = await executeBuiltinCall(registry, makeConfig(), { checkHealth: true });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.results).toHaveLength(2);
    const failing = body.results.find((r: { reachable: boolean }) => !r.reachable);
    const reachable = body.results.find((r: { reachable: boolean }) => r.reachable);
    expect(failing.error).toMatch(/spawn fail for first host/);
    expect(reachable).toBeDefined();
  });

  it('rejects extra params (.strict()) with schema_error and no spawn', async () => {
    const registry = buildRegistry(allowlistPath);
    const result = await executeBuiltinCall(registry, makeConfig(), { checkHealth: true, surprise: 1 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/schema error/i);
    expect(mockSpawnSync).not.toHaveBeenCalled();
  });

  it('writes one audit line per call with the builtin ruleId', async () => {
    mockHostExitStatus({ alpha: 0, beta: 0 });
    const registry = buildRegistry(allowlistPath);
    await executeBuiltinCall(registry, makeConfig(), {});
    await executeBuiltinCall(registry, makeConfig(), { checkHealth: true });

    const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      const event = JSON.parse(line);
      expect(event.ruleId).toBe(BUILTIN_RULE_ID);
      expect(event.toolName).toBe(BUILTIN_TOOL_NAME);
    }
    const checkedEvent = JSON.parse(lines[1]);
    expect(checkedEvent.params).toEqual({ checkHealth: true });
    expect(checkedEvent.stdoutTail).toMatch(/2\/2 reachable/);
  });

  it('fails the call when audit append fails (fail-closed)', async () => {
    const registry = buildRegistry(allowlistPath);
    const spy = vi.spyOn(fs, 'appendFileSync').mockImplementation(() => {
      throw new Error('EIO disk');
    });
    try {
      const result = await executeBuiltinCall(registry, makeConfig({ auditBestEffort: false }), {});
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toMatch(/audit append failed/i);
    } finally {
      spy.mockRestore();
    }
  });
});
