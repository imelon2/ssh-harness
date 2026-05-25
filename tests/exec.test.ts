import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cp from 'node:child_process';
import { runSsh } from '../src/exec.js';

vi.mock('node:child_process');

const mockSpawnSync = vi.mocked(cp.spawnSync);

beforeEach(() => {
  mockSpawnSync.mockReset();
});

const baseOpts = {
  sshBin: '/usr/bin/ssh',
  timeoutMs: 5000,
  maxStdoutBytes: 1024,
  maxStderrBytes: 1024,
  configPath: '/tmp/ssh_config',
};

describe('runSsh', () => {
  it('happy path: returns exitCode 0 and decoded output', () => {
    mockSpawnSync.mockReturnValue({
      status: 0,
      stdout: Buffer.from('ok\n'),
      stderr: Buffer.from(''),
      signal: null,
      pid: 123,
      output: [],
      error: undefined,
    } as unknown as ReturnType<typeof cp.spawnSync>);

    const result = runSsh('host1', ['echo', 'ok'], baseOpts);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('ok\n');
    expect(result.stderr).toBe('');
    expect(result.timedOut).toBe(false);
    expect(result.truncated).toEqual({ stdout: false, stderr: false });
  });

  it('timeout SIGTERM: sets timedOut true', () => {
    // Mock spawnSync to return SIGTERM after essentially the full timeout
    mockSpawnSync.mockImplementation(() => {
      // Simulate that timeout elapsed
      const start = performance.now();
      // burn time to simulate elapsed duration
      const end = start; // we will control via durationMs by mocking performance
      void end;
      return {
        status: null,
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
        signal: 'SIGTERM',
        pid: 123,
        output: [],
        error: undefined,
      } as unknown as ReturnType<typeof cp.spawnSync>;
    });

    // Mock performance.now so durationMs >= timeoutMs - 50
    const perfNow = vi.spyOn(performance, 'now');
    let call = 0;
    perfNow.mockImplementation(() => {
      // first call = t0, second call = t0 + timeoutMs
      return call++ === 0 ? 0 : baseOpts.timeoutMs;
    });

    const result = runSsh('host1', ['sleep', '10'], baseOpts);
    expect(result.timedOut).toBe(true);
    expect(result.signal).toBe('SIGTERM');

    perfNow.mockRestore();
  });

  it('stdout truncation: 2MB input with 1KB limit returns truncated flag', () => {
    const bigStdout = Buffer.from('a'.repeat(2 * 1024 * 1024), 'utf8');
    mockSpawnSync.mockReturnValue({
      status: 0,
      stdout: bigStdout,
      stderr: Buffer.alloc(0),
      signal: null,
      pid: 123,
      output: [],
      error: undefined,
    } as unknown as ReturnType<typeof cp.spawnSync>);

    const result = runSsh('host1', ['cat', 'bigfile'], baseOpts);

    expect(result.truncated.stdout).toBe(true);
    // stdout bytes should be <= maxStdoutBytes + length of '\n[truncated]'
    expect(Buffer.byteLength(result.stdout, 'utf8')).toBeLessThanOrEqual(
      baseOpts.maxStdoutBytes + '\n[truncated]'.length,
    );
  });

  it('multi-byte UTF-8 boundary: no replacement chars, truncated codepoint excluded', () => {
    // '한' = 0xED 0x95 0x9C (3 bytes)
    // Buffer: [a, a, a, a, 0xED, 0x95, 0x9C, a, a]
    // maxStdoutBytes = 5 → cutoff lands mid-CJK at byte 5
    const han = Buffer.from([0xed, 0x95, 0x9c]);
    const buf = Buffer.concat([
      Buffer.from('aaaa'),
      han,
      Buffer.from('aa'),
    ]);
    // buf = [61,61,61,61, ED,95,9C, 61,61] — length 9
    // maxBytes=5: slice [0..5) = [61,61,61,61,ED] — ED is a lead byte needing 3 bytes but only 1 available

    mockSpawnSync.mockReturnValue({
      status: 0,
      stdout: buf,
      stderr: Buffer.alloc(0),
      signal: null,
      pid: 123,
      output: [],
      error: undefined,
    } as unknown as ReturnType<typeof cp.spawnSync>);

    const opts = { ...baseOpts, maxStdoutBytes: 5 };
    const result = runSsh('host1', ['cat'], opts);

    expect(result.truncated.stdout).toBe(true);
    // Must NOT contain replacement character
    expect(result.stdout).not.toContain('�');
    // Must contain the truncation marker
    expect(result.stdout).toContain('\n[truncated]');
    // The 4 ASCII 'a's before the CJK char should be present
    expect(result.stdout.startsWith('aaaa')).toBe(true);
    // The CJK char itself must not appear (it was truncated)
    expect(result.stdout).not.toContain('한');
  });

  it('non-zero exit: returns exitCode 1 without throwing', () => {
    mockSpawnSync.mockReturnValue({
      status: 1,
      stdout: Buffer.from('err'),
      stderr: Buffer.from('something'),
      signal: null,
      pid: 123,
      output: [],
      error: undefined,
    } as unknown as ReturnType<typeof cp.spawnSync>);

    const result = runSsh('host1', ['false'], baseOpts);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('err');
    expect(result.stderr).toBe('something');
    expect(result.timedOut).toBe(false);
  });

  it('argv assembly: second arg to spawnSync has correct structure', () => {
    mockSpawnSync.mockReturnValue({
      status: 0,
      stdout: Buffer.from(''),
      stderr: Buffer.from(''),
      signal: null,
      pid: 123,
      output: [],
      error: undefined,
    } as unknown as ReturnType<typeof cp.spawnSync>);

    runSsh('host1', ['echo', 'hi'], baseOpts);

    const call = mockSpawnSync.mock.calls[0];
    expect(call[1]).toEqual([
      '-F', '/tmp/ssh_config',
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ConnectTimeout=5',
      'host1',
      '--',
      'echo',
      'hi',
    ]);
  });

  it('clean env: spawnSync receives only PATH in env', () => {
    mockSpawnSync.mockReturnValue({
      status: 0,
      stdout: Buffer.from(''),
      stderr: Buffer.from(''),
      signal: null,
      pid: 123,
      output: [],
      error: undefined,
    } as unknown as ReturnType<typeof cp.spawnSync>);

    runSsh('host1', ['uptime'], baseOpts);

    const opts = mockSpawnSync.mock.calls[0][2] as { env: Record<string, string> };
    expect(opts.env.PATH).toBe('/usr/bin:/bin');
    expect(Object.keys(opts.env).length).toBe(1);
  });
});
