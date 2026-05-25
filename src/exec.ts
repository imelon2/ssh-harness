import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';

export type ExecResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  durationMs: number;
  timedOut: boolean;
  truncated: { stdout: boolean; stderr: boolean };
};

export type RunSshOptions = {
  sshBin: string;
  timeoutMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  configPath: string;
  identityFile?: string;
};

function truncateAtCodepointBoundary(
  buf: Buffer,
  maxBytes: number,
): { text: string; truncated: boolean } {
  if (maxBytes === 0) {
    return { text: '[truncated]', truncated: true };
  }

  if (buf.length <= maxBytes) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
    return { text, truncated: false };
  }

  // Walk backward from maxBytes-1 to find a valid UTF-8 sequence start byte
  let validEnd = maxBytes;

  // Find the start of the last (possibly partial) codepoint
  let i = maxBytes - 1;
  while (i >= 0 && (buf[i] & 0b11000000) === 0b10000000) {
    // continuation byte — keep walking back
    i--;
  }

  if (i < 0) {
    // Entire slice is continuation bytes — nothing valid
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, 0)) + '\n[truncated]';
    return { text, truncated: true };
  }

  const leadByte = buf[i];
  let seqLen: number;
  if ((leadByte & 0b10000000) === 0) {
    seqLen = 1; // 0xxxxxxx — ASCII
  } else if ((leadByte & 0b11100000) === 0b11000000) {
    seqLen = 2; // 110xxxxx
  } else if ((leadByte & 0b11110000) === 0b11100000) {
    seqLen = 3; // 1110xxxx
  } else if ((leadByte & 0b11111000) === 0b11110000) {
    seqLen = 4; // 11110xxx
  } else {
    // Invalid lead byte — exclude it
    validEnd = i;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, validEnd)) + '\n[truncated]';
    return { text, truncated: true };
  }

  // Check if the codepoint is fully contained within [i, maxBytes)
  if (i + seqLen <= maxBytes) {
    // Fully contained — include it
    validEnd = i + seqLen;
  } else {
    // Truncated mid-sequence — exclude it
    validEnd = i;
  }

  const text = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, validEnd)) + '\n[truncated]';
  return { text, truncated: true };
}

export function runSsh(host: string, argv: string[], opts: RunSshOptions): ExecResult {
  const sshArgv = [
    '-F', opts.configPath,
    ...(opts.identityFile ? ['-i', opts.identityFile] : []),
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ConnectTimeout=5',
    host,
    '--',
    ...argv,
  ];

  const t0 = performance.now();
  const result = spawnSync(opts.sshBin, sshArgv, {
    shell: false,
    timeout: opts.timeoutMs,
    env: { PATH: '/usr/bin:/bin' },
    encoding: 'buffer',
    maxBuffer: opts.maxStdoutBytes + opts.maxStderrBytes + 1024,
  });
  const durationMs = performance.now() - t0;

  const stdoutResult = truncateAtCodepointBoundary(result.stdout as unknown as Buffer, opts.maxStdoutBytes);
  const stderrResult = truncateAtCodepointBoundary(result.stderr as unknown as Buffer, opts.maxStderrBytes);

  const timedOut =
    (result.signal === 'SIGTERM' && durationMs >= opts.timeoutMs - 50) ||
    (result.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';

  return {
    stdout: stdoutResult.text,
    stderr: stderrResult.text,
    exitCode: result.status,
    signal: result.signal,
    durationMs,
    timedOut,
    truncated: { stdout: stdoutResult.truncated, stderr: stderrResult.truncated },
  };
}
