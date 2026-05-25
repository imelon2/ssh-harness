import { describe, it, expect } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveSshConfigPath, loadConfig } from '../src/config.js';

describe('resolveSshConfigPath', () => {
  const allowlistPath = '/repo/.ssh_harness/allowlist.yaml';
  const allowlistDir = '/repo/.ssh_harness';

  it('env override wins over allowlist sshConfigRoot', () => {
    const resolved = resolveSshConfigPath('/etc/ssh/override_config', allowlistPath, './ssh_config');
    expect(resolved).toBe('/etc/ssh/override_config');
  });

  it('empty env override is ignored — falls through to allowlist', () => {
    const resolved = resolveSshConfigPath('', allowlistPath, './ssh_config');
    expect(resolved).toBe(path.resolve(allowlistDir, './ssh_config'));
  });

  it('relative sshConfigRoot resolves against allowlist directory, not cwd', () => {
    const resolved = resolveSshConfigPath(undefined, allowlistPath, './ssh_config');
    expect(resolved).toBe(path.join(allowlistDir, 'ssh_config'));
  });

  it('absolute sshConfigRoot is returned as-is', () => {
    const resolved = resolveSshConfigPath(undefined, allowlistPath, '/etc/ssh/cfg');
    expect(resolved).toBe('/etc/ssh/cfg');
  });

  it('leading ~/ in sshConfigRoot expands to home directory', () => {
    const resolved = resolveSshConfigPath(undefined, allowlistPath, '~/.ssh/work_config');
    expect(resolved).toBe(path.join(os.homedir(), '.ssh', 'work_config'));
  });

  it('bare ~ in sshConfigRoot expands to home directory', () => {
    const resolved = resolveSshConfigPath(undefined, allowlistPath, '~');
    expect(resolved).toBe(os.homedir());
  });

  it('no env and no allowlist field defaults to ~/.ssh/config', () => {
    const resolved = resolveSshConfigPath(undefined, allowlistPath, undefined);
    expect(resolved).toBe(path.join(os.homedir(), '.ssh', 'config'));
  });
});

describe('loadConfig', () => {
  it('seeds sshConfigPath with env override when SSH_HARNESS_CONFIG is set', () => {
    const config = loadConfig({ SSH_HARNESS_CONFIG: '/etc/ssh/override' });
    expect(config.sshConfigPath).toBe('/etc/ssh/override');
    expect(config.sshConfigEnvOverride).toBe('/etc/ssh/override');
  });

  it('seeds sshConfigPath with ~/.ssh/config default when env unset', () => {
    const env: NodeJS.ProcessEnv = {};
    const config = loadConfig(env);
    expect(config.sshConfigPath).toBe(path.join(os.homedir(), '.ssh', 'config'));
    expect(config.sshConfigEnvOverride).toBeUndefined();
  });
});
