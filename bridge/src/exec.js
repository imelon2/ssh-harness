import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
// Walk backward from `hardEnd-1` to find an end index <= hardEnd that does
// not split a UTF-8 codepoint. Returns the largest safe end <= hardEnd.
function backoffToCodepointEnd(buf, hardEnd) {
    if (hardEnd <= 0)
        return 0;
    if (hardEnd > buf.length)
        hardEnd = buf.length;
    let i = hardEnd - 1;
    while (i >= 0 && (buf[i] & 0b11000000) === 0b10000000) {
        i--; // skip continuation bytes
    }
    if (i < 0)
        return 0;
    const leadByte = buf[i];
    let seqLen;
    if ((leadByte & 0b10000000) === 0)
        seqLen = 1; // ASCII
    else if ((leadByte & 0b11100000) === 0b11000000)
        seqLen = 2;
    else if ((leadByte & 0b11110000) === 0b11100000)
        seqLen = 3;
    else if ((leadByte & 0b11111000) === 0b11110000)
        seqLen = 4;
    else
        return i; // invalid lead — exclude
    return (i + seqLen <= hardEnd) ? i + seqLen : i;
}
// Stream collector: accumulates chunks up to maxBytes, marks overflow when exceeded.
// Continues consuming further chunks (silently discarded) to keep the OS pipe drained
// — otherwise the child would block on a full pipe buffer.
class CappedCollector {
    maxBytes;
    buckets = [];
    bytes = 0;
    overflow = false;
    constructor(maxBytes) {
        this.maxBytes = maxBytes;
    }
    push(chunk) {
        if (this.maxBytes === 0) {
            // unlimited
            this.buckets.push(chunk);
            this.bytes += chunk.length;
            return;
        }
        if (this.overflow)
            return;
        const remaining = this.maxBytes - this.bytes;
        if (chunk.length <= remaining) {
            this.buckets.push(chunk);
            this.bytes += chunk.length;
        }
        else {
            if (remaining > 0) {
                this.buckets.push(chunk.subarray(0, remaining));
                this.bytes += remaining;
            }
            this.overflow = true;
        }
    }
    finalize() {
        const buf = Buffer.concat(this.buckets, this.bytes);
        if (!this.overflow) {
            const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
            return { text, truncated: false };
        }
        // Already byte-capped in push(). Back off only to drop a trailing partial
        // UTF-8 codepoint, then append the marker. truncated is unconditionally true.
        const end = backoffToCodepointEnd(buf, buf.length);
        const text = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, end)) + '\n[truncated]';
        return { text, truncated: true };
    }
}
export async function runSsh(host, argv, opts) {
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
    return new Promise((resolve) => {
        const t0 = performance.now();
        const proc = spawn(opts.sshBin, sshArgv, {
            shell: false,
            env: { PATH: '/usr/bin:/bin' },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        const stdoutCollector = new CappedCollector(opts.maxStdoutBytes);
        const stderrCollector = new CappedCollector(opts.maxStderrBytes);
        let timedOut = false;
        let spawnError;
        let settled = false;
        const timeoutHandle = setTimeout(() => {
            timedOut = true;
            proc.kill('SIGTERM');
            // Escalate to SIGKILL if the child ignores SIGTERM
            setTimeout(() => {
                if (!proc.killed)
                    proc.kill('SIGKILL');
            }, 2000).unref();
        }, opts.timeoutMs);
        proc.stdout?.on('data', (chunk) => stdoutCollector.push(chunk));
        proc.stderr?.on('data', (chunk) => stderrCollector.push(chunk));
        proc.on('error', (err) => {
            spawnError = err;
            // 'close' will not fire if spawn itself failed (e.g. ENOENT on sshBin) —
            // settle here instead.
            if (!settled) {
                settled = true;
                clearTimeout(timeoutHandle);
                const durationMs = performance.now() - t0;
                const stdoutResult = stdoutCollector.finalize();
                const stderrResult = stderrCollector.finalize();
                resolve({
                    stdout: stdoutResult.text,
                    stderr: stderrResult.text || spawnError.message,
                    exitCode: null,
                    signal: null,
                    durationMs,
                    timedOut,
                    truncated: { stdout: stdoutResult.truncated, stderr: stderrResult.truncated },
                });
            }
        });
        proc.on('close', (code, signal) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timeoutHandle);
            const durationMs = performance.now() - t0;
            const stdoutResult = stdoutCollector.finalize();
            const stderrResult = stderrCollector.finalize();
            resolve({
                stdout: stdoutResult.text,
                stderr: stderrResult.text,
                exitCode: code,
                signal,
                durationMs,
                timedOut,
                truncated: { stdout: stdoutResult.truncated, stderr: stderrResult.truncated },
            });
        });
    });
}
