import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cp from 'node:child_process';
import { EventEmitter } from 'node:events';
import { runSsh } from '../src/exec.js';

vi.mock('node:child_process');

const mockSpawn = vi.mocked(cp.spawn);

beforeEach(() => {
  mockSpawn.mockReset();
});

const baseOpts = {
  sshBin: '/usr/bin/ssh',
  timeoutMs: 5000,
  maxStdoutBytes: 1024,
  maxStderrBytes: 1024,
  configPath: '/tmp/ssh_config',
};

type FakeProc = EventEmitter & {
  stdout: EventEmitter;
  stderr: EventEmitter;
  kill: ReturnType<typeof vi.fn>;
  killed: boolean;
};

/**
 * Build a fake ChildProcess that emits the provided stdout/stderr chunks on
 * next tick, then a 'close' event with the given exit code/signal. Optionally
 * never closes (for timeout tests). The returned cast is intentionally loose;
 * spawn's real return type has many properties we don't need.
 */
function fakeProc(opts: {
  stdoutChunks?: Buffer[];
  stderrChunks?: Buffer[];
  exitCode?: number | null;
  signal?: NodeJS.Signals | null;
  emitError?: Error;
  neverClose?: boolean;
  closeDelayMs?: number;
}): FakeProc {
  const proc = new EventEmitter() as FakeProc;
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  proc.killed = false;
  proc.kill = vi.fn((_sig?: NodeJS.Signals | number) => {
    proc.killed = true;
    // Simulate kernel reaping the killed child shortly after
    setImmediate(() => {
      proc.emit('close', null, 'SIGTERM');
    });
    return true;
  });

  if (opts.emitError !== undefined) {
    setImmediate(() => proc.emit('error', opts.emitError));
    return proc;
  }

  const emit = () => {
    for (const c of opts.stdoutChunks ?? []) proc.stdout.emit('data', c);
    for (const c of opts.stderrChunks ?? []) proc.stderr.emit('data', c);
    if (!opts.neverClose) {
      proc.emit('close', opts.exitCode ?? 0, opts.signal ?? null);
    }
  };

  if (opts.closeDelayMs !== undefined) {
    setTimeout(emit, opts.closeDelayMs);
  } else {
    setImmediate(emit);
  }
  return proc;
}

describe('runSsh', () => {
  it('happy path: returns exitCode 0 and decoded output', async () => {
    mockSpawn.mockReturnValue(
      fakeProc({ stdoutChunks: [Buffer.from('ok\n')], exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    const result = await runSsh('host1', ['echo', 'ok'], baseOpts);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('ok\n');
    expect(result.stderr).toBe('');
    expect(result.timedOut).toBe(false);
    expect(result.truncated).toEqual({ stdout: false, stderr: false });
  });

  it('timeout: setTimeout fires SIGTERM and sets timedOut true', async () => {
    let theProc: FakeProc | undefined;
    mockSpawn.mockImplementation((..._args: unknown[]) => {
      theProc = fakeProc({ neverClose: true });
      return theProc as unknown as cp.ChildProcess;
    });

    const result = await runSsh('host1', ['sleep', '10'], { ...baseOpts, timeoutMs: 20 });

    expect(result.timedOut).toBe(true);
    expect(theProc?.kill).toHaveBeenCalledWith('SIGTERM');
    expect(result.signal).toBe('SIGTERM');
    expect(result.exitCode).toBeNull();
  });

  it('stdout truncation: 2MB input with 1KB limit returns truncated flag', async () => {
    const bigStdout = Buffer.from('a'.repeat(2 * 1024 * 1024), 'utf8');
    mockSpawn.mockReturnValue(
      fakeProc({ stdoutChunks: [bigStdout], exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    const result = await runSsh('host1', ['cat', 'bigfile'], baseOpts);

    expect(result.truncated.stdout).toBe(true);
    // stdout bytes should be <= maxStdoutBytes + length of '\n[truncated]'
    expect(Buffer.byteLength(result.stdout, 'utf8')).toBeLessThanOrEqual(
      baseOpts.maxStdoutBytes + '\n[truncated]'.length,
    );
  });

  it('stdout truncation across multiple chunks: per-chunk discard, single truncation marker', async () => {
    // Three 600-byte chunks → total 1800 bytes, cap 1024 → overflow on 2nd chunk
    const chunks = [
      Buffer.from('a'.repeat(600)),
      Buffer.from('b'.repeat(600)),
      Buffer.from('c'.repeat(600)),
    ];
    mockSpawn.mockReturnValue(
      fakeProc({ stdoutChunks: chunks, exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    const result = await runSsh('host1', ['cat'], baseOpts);

    expect(result.truncated.stdout).toBe(true);
    expect(result.stdout).toContain('[truncated]');
    // First 600 a's preserved entirely, plus 424 b's, then overflow.
    // Inspect the captured portion BEFORE the truncation marker.
    const body = result.stdout.split('\n[truncated]')[0];
    expect(body).toBe('a'.repeat(600) + 'b'.repeat(424));
  });

  it('multi-byte UTF-8 boundary: no replacement chars, truncated codepoint excluded', async () => {
    // '한' = 0xED 0x95 0x9C (3 bytes)
    // Buffer: [a, a, a, a, 0xED, 0x95, 0x9C, a, a]
    // maxStdoutBytes = 5 → cutoff lands mid-CJK at byte 5
    const han = Buffer.from([0xed, 0x95, 0x9c]);
    const buf = Buffer.concat([
      Buffer.from('aaaa'),
      han,
      Buffer.from('aa'),
    ]);

    mockSpawn.mockReturnValue(
      fakeProc({ stdoutChunks: [buf], exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    const opts = { ...baseOpts, maxStdoutBytes: 5 };
    const result = await runSsh('host1', ['cat'], opts);

    expect(result.truncated.stdout).toBe(true);
    expect(result.stdout).not.toContain('�'); // no U+FFFD replacement char
    expect(result.stdout).toContain('\n[truncated]');
    expect(result.stdout.startsWith('aaaa')).toBe(true);
    expect(result.stdout).not.toContain('한');
  });

  it('maxStdoutBytes=0 sentinel: 2MB stdout passes through untouched', async () => {
    const bigStdout = Buffer.from('a'.repeat(2 * 1024 * 1024), 'utf8');
    mockSpawn.mockReturnValue(
      fakeProc({ stdoutChunks: [bigStdout], exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    const opts = { ...baseOpts, maxStdoutBytes: 0 };
    const result = await runSsh('host1', ['cat'], opts);

    expect(result.truncated.stdout).toBe(false);
    expect(Buffer.byteLength(result.stdout, 'utf8')).toBe(bigStdout.length);
    expect(result.stdout).not.toContain('[truncated]');
  });

  it('maxStderrBytes=0 sentinel: stderr passes through untouched', async () => {
    const bigStderr = Buffer.from('e'.repeat(2 * 1024 * 1024), 'utf8');
    mockSpawn.mockReturnValue(
      fakeProc({ stderrChunks: [bigStderr], exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    const opts = { ...baseOpts, maxStderrBytes: 0 };
    const result = await runSsh('host1', ['cat'], opts);

    expect(result.truncated.stderr).toBe(false);
    expect(Buffer.byteLength(result.stderr, 'utf8')).toBe(bigStderr.length);
    expect(result.stderr).not.toContain('[truncated]');
  });

  it('non-zero exit: returns exitCode 1 without throwing', async () => {
    mockSpawn.mockReturnValue(
      fakeProc({
        stdoutChunks: [Buffer.from('err')],
        stderrChunks: [Buffer.from('something')],
        exitCode: 1,
      }) as unknown as cp.ChildProcess,
    );

    const result = await runSsh('host1', ['false'], baseOpts);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('err');
    expect(result.stderr).toBe('something');
    expect(result.timedOut).toBe(false);
  });

  it('spawn error (ENOENT): settles with exitCode null and surfaces error message in stderr', async () => {
    mockSpawn.mockReturnValue(
      fakeProc({ emitError: new Error('spawn /nope ENOENT') }) as unknown as cp.ChildProcess,
    );

    const result = await runSsh('host1', ['nope'], baseOpts);

    expect(result.exitCode).toBeNull();
    expect(result.stderr).toContain('ENOENT');
    expect(result.timedOut).toBe(false);
  });

  it('argv assembly: second arg to spawn has correct structure', async () => {
    mockSpawn.mockReturnValue(
      fakeProc({ exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    await runSsh('host1', ['echo', 'hi'], baseOpts);

    const call = mockSpawn.mock.calls[0];
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

  it('clean env: spawn receives only PATH in env, shell:false, stdio piped', async () => {
    mockSpawn.mockReturnValue(
      fakeProc({ exitCode: 0 }) as unknown as cp.ChildProcess,
    );

    await runSsh('host1', ['uptime'], baseOpts);

    const opts = mockSpawn.mock.calls[0][2] as {
      env: Record<string, string>;
      shell: boolean;
      stdio: unknown;
    };
    expect(opts.env.PATH).toBe('/usr/bin:/bin');
    expect(Object.keys(opts.env).length).toBe(1);
    expect(opts.shell).toBe(false);
    expect(opts.stdio).toEqual(['ignore', 'pipe', 'pipe']);
  });
});
