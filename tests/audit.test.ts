import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { appendAudit, redactParams, AuditAppendError, type AuditEvent } from '../src/audit.js';
import type { ParamSpec } from '../src/allowlist.js';

vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>();
  return { ...actual };
});

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-harness-audit-'));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    ts: new Date().toISOString(),
    ruleId: 'r1',
    toolName: 'ssh_test',
    outcome: 'ok',
    params: { host: 'localhost' },
    argv: ['uptime'],
    host: 'localhost',
    exitCode: 0,
    durationMs: 12.3,
    stdoutTail: 'ok',
    stderrTail: '',
    ...overrides,
  };
}

describe('appendAudit', () => {
  it('3 events appended in order', () => {
    const file = path.join(tmp, 'audit.log');
    appendAudit(file, makeEvent({ ruleId: 'a' }), { bestEffort: false });
    appendAudit(file, makeEvent({ ruleId: 'b' }), { bestEffort: false });
    appendAudit(file, makeEvent({ ruleId: 'c' }), { bestEffort: false });
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    expect(lines.length).toBe(3);
    expect(JSON.parse(lines[0]).ruleId).toBe('a');
    expect(JSON.parse(lines[1]).ruleId).toBe('b');
    expect(JSON.parse(lines[2]).ruleId).toBe('c');
  });

  it('redactParams replaces secret values', () => {
    const specs: Record<string, ParamSpec> = {
      pw: { type: 'string', secret: true, pattern: '^.+$' },
      user: { type: 'string', enum: ['root'] },
    };
    const result = redactParams({ pw: 'hunter2', user: 'root' }, specs);
    expect(result).toEqual({ pw: '[REDACTED]', user: 'root' });
  });

  it('file created with mode 0o600', () => {
    const file = path.join(tmp, 'fresh.log');
    appendAudit(file, makeEvent(), { bestEffort: false });
    const stat = fs.statSync(file);
    // Skip the mode check on Windows; on POSIX assert at least the owner-rw mode bits
    if (process.platform !== 'win32') {
      expect(stat.mode & 0o777).toBe(0o600);
    }
    expect(fs.existsSync(file)).toBe(true);
  });

  it('long param value not truncated by audit; stdoutTail respected', () => {
    const longValue = 'x'.repeat(10000);
    const tail = 'y'.repeat(512);
    const file = path.join(tmp, 'audit.log');
    appendAudit(file, makeEvent({
      params: { host: 'localhost', big: longValue },
      stdoutTail: tail,
    }), { bestEffort: false });
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8').trim());
    expect(parsed.params.big.length).toBe(10000);     // not truncated by audit
    expect(parsed.stdoutTail.length).toBe(512);
  });

  it('fail-closed throws; best-effort logs and returns', () => {
    const spy = vi.spyOn(fs, 'appendFileSync').mockImplementation(() => {
      throw new Error('EIO disk failure');
    });
    const file = path.join(tmp, 'audit.log');
    try {
      // fail-closed default: throws
      expect(() => appendAudit(file, makeEvent(), { bestEffort: false }))
        .toThrow(AuditAppendError);
      // best-effort: returns normally
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      expect(() => appendAudit(file, makeEvent(), { bestEffort: true })).not.toThrow();
      expect(stderrSpy).toHaveBeenCalled();
      stderrSpy.mockRestore();
    } finally {
      spy.mockRestore();
    }
  });

  it('CJK content at tail boundary survives JSON round-trip', () => {
    const cjkTail = '한글테스트' + '한'.repeat(100);
    const file = path.join(tmp, 'audit.log');
    appendAudit(file, makeEvent({ stdoutTail: cjkTail }), { bestEffort: false });
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8').trim());
    expect(parsed.stdoutTail).toBe(cjkTail);  // exact round-trip
  });
});
