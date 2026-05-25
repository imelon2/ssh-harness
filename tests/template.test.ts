import { describe, it, expect } from 'vitest';
import { renderArgv, MissingPlaceholderError } from '../src/template.js';
import type { RuleDef } from '../src/allowlist.js';

const baseRule = (override: Partial<RuleDef> = {}): RuleDef => ({
  id: 'r1',
  tool: { name: 'r1', description: 'd' },
  params: {},
  template: { host: '{host}', argv: ['true'] },
  ...override,
});

describe('renderArgv', () => {
  it('docker logs argv assembly', () => {
    const rule = baseRule({
      template: { host: '{host}', argv: ['docker', 'logs', '--tail', '{lines}', '{container}'] },
    });
    const { host, argv } = renderArgv(rule, { host: 'localhost', lines: 200, container: 'api' });
    expect(host).toBe('localhost');
    expect(argv).toEqual(['docker', 'logs', '--tail', '200', 'api']);
  });

  it('embedded placeholder', () => {
    const rule = baseRule({ template: { host: '{host}', argv: ['--tail={lines}'] } });
    const { argv } = renderArgv(rule, { host: 'h', lines: 200 });
    expect(argv).toEqual(['--tail=200']);
  });

  it('missing param throws MissingPlaceholderError with key', () => {
    const rule = baseRule({ template: { host: '{host}', argv: ['{missing}'] } });
    let thrown: unknown;
    try {
      renderArgv(rule, { host: 'h' });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(MissingPlaceholderError);
    expect((thrown as MissingPlaceholderError).key).toBe('missing');
  });

  it('shell-meta value passes through literally', () => {
    const rule = baseRule({ template: { host: '{host}', argv: ['echo', '{msg}'] } });
    const { argv } = renderArgv(rule, { host: 'h', msg: '; rm -rf /' });
    expect(argv).toEqual(['echo', '; rm -rf /']);
    expect(argv.length).toBe(2);
  });

  it('integer coerced to string', () => {
    const rule = baseRule({ template: { host: '{host}', argv: ['{n}'] } });
    const { argv } = renderArgv(rule, { host: 'h', n: 42 });
    expect(argv).toEqual(['42']);
    expect(typeof argv[0]).toBe('string');
  });

  it('template.host returns host param', () => {
    const rule = baseRule({ template: { host: '{host}', argv: ['true'] } });
    const { host } = renderArgv(rule, { host: 'prod-1' });
    expect(host).toBe('prod-1');
  });
});
