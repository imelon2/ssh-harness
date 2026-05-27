import { describe, it, expect } from 'vitest';
import { runSsh } from '../src/exec.js';

const RUN_E2E = process.env.SSH_HARNESS_E2E === '1';

describe.skipIf(!RUN_E2E)('exec e2e', () => {
  it('runs uptime against localhost', async () => {
    const result = await runSsh('localhost', ['uptime'], {
      sshBin: '/usr/bin/ssh',
      timeoutMs: 10000,
      maxStdoutBytes: 4096,
      maxStderrBytes: 4096,
      configPath: `${process.cwd()}/.ssh_harness/ssh_config`,
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/load average/);
  });
});
