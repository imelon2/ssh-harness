import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  loadAllowlist,
  buildRegistry,
  expandWildcardHosts,
  lintAllowlist,
  patternRejectsDashLead,
  type Allowlist,
} from '../src/allowlist.js';

// ---------------------------------------------------------------------------
// Helper: write a YAML string to a temp file and return the path
// ---------------------------------------------------------------------------
function writeTmp(yaml: string, name = 'tmp.yaml'): string {
  const p = path.join(os.tmpdir(), `ssh-harness-test-${Date.now()}-${name}`);
  fs.writeFileSync(p, yaml, 'utf8');
  return p;
}

// ---------------------------------------------------------------------------
// Minimal valid rule factory
// ---------------------------------------------------------------------------
function minimalRule(id: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    tool: { name: 'get_uptime', description: 'Get uptime' },
    params: {
      host: { type: 'string', enum: ['localhost'] },
    },
    template: { host: '{host}', argv: ['uptime'] },
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// 1. Parse sample YAML — 1 rule, hosts: [localhost]
// ---------------------------------------------------------------------------
describe('allowlist tests', () => {
  it('1. parses sample YAML with 1 rule', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: [localhost]
rules:
  - id: get_uptime
    tool:
      name: get_uptime
      description: Returns uptime of a remote host
    params:
      host:
        type: string
        enum: [localhost]
    template:
      host: "{host}"
      argv: [uptime]
`;
    const p = writeTmp(yaml, '1.yaml');
    const result = loadAllowlist(p);
    expect(result.rules.length).toBe(1);
    expect(result.hosts.allowHosts).toEqual(['localhost']);
    expect(result.hosts.sshConfigRoot).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // 2. YAML anchor reuse — 3 rules sharing &hosts
  // -------------------------------------------------------------------------
  it('2. YAML anchor reuse — 3 rules share the same hosts enum', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: &hosts [a, b]
rules:
  - id: rule1
    tool: { name: rule1, description: d }
    params:
      host: { type: string, enum: *hosts }
    template: { host: "{host}", argv: [uptime] }
  - id: rule2
    tool: { name: rule2, description: d }
    params:
      host: { type: string, enum: *hosts }
    template: { host: "{host}", argv: [uptime] }
  - id: rule3
    tool: { name: rule3, description: d }
    params:
      host: { type: string, enum: *hosts }
    template: { host: "{host}", argv: [uptime] }
`;
    const p = writeTmp(yaml, '2.yaml');
    const result = loadAllowlist(p);
    expect(result.rules.length).toBe(3);
    for (const rule of result.rules) {
      expect(rule.params['host']?.enum).toEqual(['a', 'b']);
    }
  });

  // -------------------------------------------------------------------------
  // 3. Duplicate id → ERROR with /duplicate.*id/i
  // -------------------------------------------------------------------------
  it('3. duplicate rule id returns lint error matching /duplicate.*id/i', () => {
    const allowlist: Allowlist = {
      version: 2,
      hosts: { allowHosts: ['localhost'] },
      rules: [
        {
          id: 'get_x',
          tool: { name: 'get_x', description: 'd' },
          params: { host: { type: 'string', enum: ['localhost'] } },
          template: { host: '{host}', argv: ['uptime'] },
        },
        {
          id: 'get_x',
          tool: { name: 'get_x', description: 'd' },
          params: { host: { type: 'string', enum: ['localhost'] } },
          template: { host: '{host}', argv: ['uptime'] },
        },
      ],
    };
    const errs = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const dupeErr = errs.find((e) => /duplicate.*id/i.test(e));
    expect(dupeErr).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // 4. Missing template.host → loadAllowlist throws
  // -------------------------------------------------------------------------
  it('4. missing template.host causes loadAllowlist to throw', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: [localhost]
rules:
  - id: bad_rule
    tool: { name: bad_rule, description: d }
    params:
      host: { type: string, enum: [localhost] }
    template:
      argv: [uptime]
`;
    const p = writeTmp(yaml, '4.yaml');
    expect(() => loadAllowlist(p)).toThrow();
  });

  // -------------------------------------------------------------------------
  // 5. Unknown placeholder → lint error mentioning token name
  // -------------------------------------------------------------------------
  it('5. unknown placeholder {unknown} in argv produces lint error', () => {
    const allowlist: Allowlist = {
      version: 2,
      hosts: { allowHosts: ['localhost'] },
      rules: [
        {
          id: 'rule_a',
          tool: { name: 'rule_a', description: 'd' },
          params: { host: { type: 'string', enum: ['localhost'] } },
          template: { host: '{host}', argv: ['uptime', '{unknown}'] },
        },
      ],
    };
    const errs = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const placeholderErr = errs.find((e) => e.includes('unknown'));
    expect(placeholderErr).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // 6. Mutation verb — ERROR when strict, WARN when not strict
  // -------------------------------------------------------------------------
  it('6. mutation verb rm: ERROR in strict mode, WARN in non-strict mode', () => {
    const allowlist: Allowlist = {
      version: 2,
      hosts: { allowHosts: ['localhost'] },
      rules: [
        {
          id: 'bad_rm',
          tool: { name: 'bad_rm', description: 'd' },
          params: { host: { type: 'string', enum: ['localhost'] } },
          template: { host: '{host}', argv: ['rm', '-rf', '/'] },
        },
      ],
    };
    const strictErrs = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const nonStrictErrs = lintAllowlist(allowlist, { strict: false, maxRules: 40 });

    const strictErr = strictErrs.find((e) => e.startsWith('[ERROR]') && e.includes('bad_rm'));
    expect(strictErr).toBeDefined();

    // In non-strict mode the mutation message should be WARN not ERROR
    const nonStrictError = nonStrictErrs.find(
      (e) => e.startsWith('[ERROR]') && e.includes('bad_rm') && e.includes('mutation'),
    );
    const nonStrictWarn = nonStrictErrs.find(
      (e) => e.startsWith('[WARN]') && e.includes('bad_rm'),
    );
    expect(nonStrictError).toBeUndefined();
    expect(nonStrictWarn).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // 7. integer without maximum → ERROR mentioning param name and "maximum"
  // -------------------------------------------------------------------------
  it('7. integer param without maximum produces lint error', () => {
    const allowlist: Allowlist = {
      version: 2,
      hosts: { allowHosts: ['localhost'] },
      rules: [
        {
          id: 'rule_int',
          tool: { name: 'rule_int', description: 'd' },
          params: {
            host: { type: 'string', enum: ['localhost'] },
            n: { type: 'integer', minimum: 1 },
          },
          template: { host: '{host}', argv: ['count', '{n}'] },
        },
      ],
    };
    const errs = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const intErr = errs.find((e) => e.includes('"n"') && e.includes('maximum'));
    expect(intErr).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // 8. string without enum or pattern → ERROR mentioning param name
  // -------------------------------------------------------------------------
  it('8. string param without enum or pattern produces lint error', () => {
    const allowlist: Allowlist = {
      version: 2,
      hosts: { allowHosts: ['localhost'] },
      rules: [
        {
          id: 'rule_str',
          tool: { name: 'rule_str', description: 'd' },
          params: {
            host: { type: 'string', enum: ['localhost'] },
            s: { type: 'string' },
          },
          template: { host: '{host}', argv: ['cmd', '{s}'] },
        },
      ],
    };
    const errs = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const strErr = errs.find((e) => e.includes('"s"') && (e.includes('enum') || e.includes('pattern')));
    expect(strErr).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // 9. pattern '.*' matches dash-leading → ERROR
  // -------------------------------------------------------------------------
  it('9. pattern matching dash-leading strings produces lint error', () => {
    const allowlist: Allowlist = {
      version: 2,
      hosts: { allowHosts: ['localhost'] },
      rules: [
        {
          id: 'rule_pat',
          tool: { name: 'rule_pat', description: 'd' },
          params: {
            host: { type: 'string', enum: ['localhost'] },
            s: { type: 'string', pattern: '.*' },
          },
          template: { host: '{host}', argv: ['cmd', '{s}'] },
        },
      ],
    };
    const errs = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const patErr = errs.find((e) => e.includes('"s"') && e.includes('pattern'));
    expect(patErr).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // 10. patternRejectsDashLead positive and negative cases
  // -------------------------------------------------------------------------
  it('10. patternRejectsDashLead positive and negative cases', () => {
    expect(patternRejectsDashLead('^[a-z]+$')).toBe(true);
    expect(patternRejectsDashLead('^[a-z][a-z0-9_]*$')).toBe(true);
    expect(patternRejectsDashLead('^(api|web|db)-[0-9]+$')).toBe(true);
    expect(patternRejectsDashLead('.*')).toBe(false);
    expect(patternRejectsDashLead('^.+$')).toBe(false);
    expect(patternRejectsDashLead('^-?[a-z]+$')).toBe(false);
    expect(patternRejectsDashLead('^[a-z-]+$')).toBe(false);
  });

  // -------------------------------------------------------------------------
  // 11. empty enum → ERROR
  // -------------------------------------------------------------------------
  it('11. empty enum produces lint error', () => {
    const allowlist: Allowlist = {
      version: 2,
      hosts: { allowHosts: ['localhost'] },
      rules: [
        {
          id: 'rule_enum',
          tool: { name: 'rule_enum', description: 'd' },
          params: {
            host: { type: 'string', enum: ['localhost'] },
            s: { type: 'string', enum: [] },
          },
          template: { host: '{host}', argv: ['cmd', '{s}'] },
        },
      ],
    };
    const errs = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const emptyErr = errs.find((e) => e.includes('"s"') && e.includes('empty'));
    expect(emptyErr).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // 12. maxRules: 41 rules → ERROR; same with maxRules:50 → no error
  // -------------------------------------------------------------------------
  it('12. maxRules enforcement', () => {
    const rules = Array.from({ length: 41 }, (_, i) => ({
      id: `rule_${i}`,
      tool: { name: `rule_${i}`, description: 'd' },
      params: { host: { type: 'string' as const, enum: ['localhost'] } },
      template: { host: '{host}', argv: ['uptime'] },
    }));
    const allowlist: Allowlist = { version: 2, hosts: { allowHosts: ['localhost'] }, rules };

    const errs40 = lintAllowlist(allowlist, { strict: true, maxRules: 40 });
    const maxErr = errs40.find((e) => e.includes('maxRules') || e.includes('exceeds'));
    expect(maxErr).toBeDefined();

    const errs50 = lintAllowlist(allowlist, { strict: true, maxRules: 50 });
    const maxErr50 = errs50.find((e) => e.includes('maxRules') || e.includes('exceeds'));
    expect(maxErr50).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // 13. Registry.get / count / list
  // -------------------------------------------------------------------------
  it('13. Registry.get, count, list', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: [localhost]
rules:
  - id: rule_a
    tool: { name: rule_a, description: d }
    params:
      host: { type: string, enum: [localhost] }
    template: { host: "{host}", argv: [uptime] }
  - id: rule_b
    tool: { name: rule_b, description: d }
    params:
      host: { type: string, enum: [localhost] }
    template: { host: "{host}", argv: [df] }
`;
    const p = writeTmp(yaml, '13.yaml');
    const registry = buildRegistry(p);
    expect(registry.count()).toBe(2);
    expect(registry.list().length).toBe(2);
    expect(registry.get('unknown')).toBeUndefined();
    const found = registry.get('rule_a');
    expect(found).toBeDefined();
    expect(found?.id).toBe('rule_a');
  });

  // -------------------------------------------------------------------------
  // 14. Registry.settings shallow merge
  // -------------------------------------------------------------------------
  it('14. Registry.settings shallow merge over defaults', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: [localhost]
settings:
  timeoutMs: 5000
rules:
  - id: rule_a
    tool: { name: rule_a, description: d }
    params:
      host: { type: string, enum: [localhost] }
    template: { host: "{host}", argv: [uptime] }
`;
    const p = writeTmp(yaml, '14.yaml');
    const registry = buildRegistry(p);
    const s = registry.settings();
    expect(s.timeoutMs).toBe(5000);
    expect(s.maxStdoutBytes).toBe(262144);
    expect(s.maxStderrBytes).toBe(65536);
    expect(s.sshBin).toBe('/usr/bin/ssh');
    expect(s.identityFile).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // expandWildcardHosts
  // -------------------------------------------------------------------------
  it('15. expandWildcardHosts is a no-op when allowHosts is a literal list', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: [alpha, beta]
rules:
  - id: r1
    tool: { name: r1, description: d }
    params: { host: { type: string, enum: [alpha, beta] } }
    template: { host: "{host}", argv: [uptime] }
`;
    const p = writeTmp(yaml, '15.yaml');
    const al = loadAllowlist(p);
    expandWildcardHosts(al, new Set(['alpha', 'beta', 'gamma']));
    expect(al.hosts.allowHosts).toEqual(['alpha', 'beta']);
    expect(al.rules[0].params.host.enum).toEqual(['alpha', 'beta']);
  });

  it('16. expandWildcardHosts expands allowHosts and rule enums when ["*"]', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: &hosts ["*"]
rules:
  - id: r1
    tool: { name: r1, description: d }
    params: { host: { type: string, enum: *hosts } }
    template: { host: "{host}", argv: [uptime] }
`;
    const p = writeTmp(yaml, '16.yaml');
    const al = loadAllowlist(p);
    expandWildcardHosts(al, new Set(['k8s-master', 'web-1']));
    expect(al.hosts.allowHosts).toEqual(['k8s-master', 'web-1']);
    expect(al.rules[0].params.host.enum).toEqual(['k8s-master', 'web-1']);
  });

  it('17. expandWildcardHosts also expands literal enum: ["*"] without anchor', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: ["*"]
rules:
  - id: r1
    tool: { name: r1, description: d }
    params: { host: { type: string, enum: ["*"] } }
    template: { host: "{host}", argv: [uptime] }
`;
    const p = writeTmp(yaml, '17.yaml');
    const al = loadAllowlist(p);
    expandWildcardHosts(al, new Set(['alpha']));
    expect(al.hosts.allowHosts).toEqual(['alpha']);
    expect(al.rules[0].params.host.enum).toEqual(['alpha']);
  });

  it('18. expandWildcardHosts throws when ssh_config has no usable aliases', () => {
    const yaml = `
version: 2
hosts:
  allowHosts: ["*"]
rules:
  - id: r1
    tool: { name: r1, description: d }
    params: { host: { type: string, enum: ["*"] } }
    template: { host: "{host}", argv: [uptime] }
`;
    const p = writeTmp(yaml, '18.yaml');
    const al = loadAllowlist(p);
    expect(() => expandWildcardHosts(al, new Set())).toThrow(/expanded to empty list/i);
  });
});
