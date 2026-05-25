import * as fs from 'fs';
import { parse as yamlParse } from 'yaml';
import { z } from 'zod';
// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------
const DEFAULTS = {
    timeoutMs: 30000,
    maxStdoutBytes: 262144,
    maxStderrBytes: 65536,
    sshBin: '/usr/bin/ssh',
    identityFile: undefined,
};
// ---------------------------------------------------------------------------
// Meta-Zod schema for loader validation
// ---------------------------------------------------------------------------
const ParamSpecSchema = z.object({
    type: z.enum(['string', 'integer']),
    enum: z.array(z.union([z.string(), z.number()])).optional(),
    pattern: z.string().optional(),
    minimum: z.number().optional(),
    maximum: z.number().optional(),
    default: z.union([z.string(), z.number()]).optional(),
    description: z.string().optional(),
    secret: z.boolean().optional(),
});
const RuleTemplateSchema = z.object({
    host: z.string(),
    argv: z.array(z.string()),
});
const RuleDefSchema = z.object({
    id: z.string(),
    tool: z.object({
        name: z.string(),
        description: z.string(),
    }),
    params: z.record(z.string(), ParamSpecSchema),
    template: RuleTemplateSchema,
});
const GlobalSettingsSchema = z.object({
    timeoutMs: z.number().optional(),
    maxStdoutBytes: z.number().optional(),
    maxStderrBytes: z.number().optional(),
    sshBin: z.string().optional(),
    identityFile: z.string().optional(),
});
const HostsBlockSchema = z.object({
    allowHosts: z.array(z.string()).nonempty(),
    sshConfigRoot: z.string().optional(),
});
const AllowlistSchema = z.object({
    version: z.literal(2),
    settings: GlobalSettingsSchema.optional(),
    hosts: HostsBlockSchema,
    rules: z.array(RuleDefSchema),
});
// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------
export class Registry {
    allowlist;
    constructor(allowlist) {
        this.allowlist = allowlist;
    }
    get(ruleId) {
        return this.allowlist.rules.find((r) => r.id === ruleId);
    }
    list() {
        return this.allowlist.rules;
    }
    count() {
        return this.allowlist.rules.length;
    }
    hosts() {
        return this.allowlist.hosts.allowHosts;
    }
    sshConfigRoot() {
        return this.allowlist.hosts.sshConfigRoot;
    }
    settings() {
        return { ...DEFAULTS, ...(this.allowlist.settings ?? {}) };
    }
    raw() {
        return this.allowlist;
    }
}
// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------
export function loadAllowlist(path) {
    const text = fs.readFileSync(path, 'utf8');
    const parsed = yamlParse(text);
    const result = AllowlistSchema.safeParse(parsed);
    if (!result.success) {
        throw new Error(`Invalid allowlist at ${path}: ${result.error.message}`);
    }
    return result.data;
}
export function buildRegistry(path) {
    return new Registry(loadAllowlist(path));
}
// ---------------------------------------------------------------------------
// Wildcard expansion
// ---------------------------------------------------------------------------
/**
 * Expand `allowHosts: ["*"]` (and any string-param `enum: ["*"]`) to the
 * concrete Host aliases declared in the resolved ssh_config. Mutates the
 * passed Allowlist in place. No-op when allowHosts is a literal list.
 *
 * Throws if `["*"]` is used but the ssh_config has zero declared aliases
 * (after `Host *` is filtered out by parseHostAliases) — better to fail fast
 * than silently register zero tools.
 */
export function expandWildcardHosts(allowlist, aliases) {
    const isWildcardOnly = (arr) => Array.isArray(arr) && arr.length === 1 && arr[0] === '*';
    if (!isWildcardOnly(allowlist.hosts.allowHosts))
        return;
    const expanded = Array.from(new Set(Array.from(aliases).filter((a) => a !== '*'))).sort();
    if (expanded.length === 0) {
        throw new Error('allowHosts: ["*"] expanded to empty list — ssh_config has no Host aliases other than wildcards');
    }
    replaceArrayContents(allowlist.hosts.allowHosts, expanded);
    for (const rule of allowlist.rules) {
        for (const spec of Object.values(rule.params)) {
            if (spec.type === 'string' && isWildcardOnly(spec.enum)) {
                replaceArrayContents(spec.enum, expanded);
            }
        }
    }
}
function replaceArrayContents(target, next) {
    target.length = 0;
    target.push(...next);
}
// ---------------------------------------------------------------------------
// Lint
// ---------------------------------------------------------------------------
const TOOL_NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const PLACEHOLDER_RE = /\{(\w+)\}/g;
const MUTATION_VERBS = new Set([
    'rm', 'mv', 'cp', 'dd', 'kill', 'restart', 'reboot', 'shutdown',
    'chmod', 'chown', 'truncate',
]);
const SYSTEMCTL_ACTIONS = new Set(['start', 'stop', 'restart', 'disable', 'enable']);
const DOCKER_ACTIONS = new Set(['rm', 'stop', 'restart', 'kill']);
// Simple heuristic for nested quantifier detection
const UNSAFE_PATTERN_RE = /\([^)]*[+*][^)]*\)[+*]/;
export function lintAllowlist(a, opts) {
    const errors = [];
    // Check 9: maxRules
    if (a.rules.length > opts.maxRules) {
        errors.push(`[ERROR] rules count ${a.rules.length} exceeds maxRules ${opts.maxRules}`);
    }
    const seenIds = new Set();
    for (const rule of a.rules) {
        const id = rule.id;
        // Check 1: unique id
        if (seenIds.has(id)) {
            errors.push(`[ERROR] rule "${id}": duplicate rule id`);
        }
        seenIds.add(id);
        // Check 2: tool.name format
        if (!TOOL_NAME_RE.test(rule.tool.name)) {
            errors.push(`[ERROR] rule "${id}": tool.name "${rule.tool.name}" does not match /^[a-z][a-z0-9_]{0,63}$/`);
        }
        // Check 3: placeholder resolution
        const paramKeys = new Set(Object.keys(rule.params));
        const templateStrings = [rule.template.host, ...rule.template.argv];
        for (const tmpl of templateStrings) {
            let m;
            PLACEHOLDER_RE.lastIndex = 0;
            while ((m = PLACEHOLDER_RE.exec(tmpl)) !== null) {
                const token = m[1];
                if (token !== 'host' && !paramKeys.has(token)) {
                    errors.push(`[ERROR] rule "${id}": placeholder {${token}} not found in params`);
                }
            }
        }
        // Check 4: mutation verb
        const cmd = rule.template.argv[0];
        let isMutation = false;
        let mutationReason = '';
        if (cmd !== undefined) {
            if (MUTATION_VERBS.has(cmd)) {
                isMutation = true;
                mutationReason = `argv[0] is mutation verb "${cmd}"`;
            }
            else if (cmd === 'systemctl' && rule.template.argv[1] !== undefined && SYSTEMCTL_ACTIONS.has(rule.template.argv[1])) {
                isMutation = true;
                mutationReason = `systemctl ${rule.template.argv[1]} is a mutation operation`;
            }
            else if (cmd === 'docker' && rule.template.argv[1] !== undefined && DOCKER_ACTIONS.has(rule.template.argv[1])) {
                isMutation = true;
                mutationReason = `docker ${rule.template.argv[1]} is a mutation operation`;
            }
        }
        if (isMutation) {
            const level = opts.strict ? '[ERROR]' : '[WARN]';
            errors.push(`${level} rule "${id}": ${mutationReason}`);
        }
        // Check 5 & 6 & 7 & 8: param-level checks
        for (const [paramName, spec] of Object.entries(rule.params)) {
            if (spec.type === 'integer') {
                // Check 5: integer must have maximum
                if (spec.maximum === undefined) {
                    errors.push(`[ERROR] rule "${id}" param "${paramName}": type:integer requires maximum`);
                }
            }
            if (spec.type === 'string') {
                // Check 6: string must have enum or pattern
                if (spec.enum === undefined && spec.pattern === undefined) {
                    errors.push(`[ERROR] rule "${id}" param "${paramName}": type:string requires enum or pattern`);
                }
                // Check 7: pattern must reject dash-leading
                if (spec.pattern !== undefined && !patternRejectsDashLead(spec.pattern)) {
                    errors.push(`[ERROR] rule "${id}" param "${paramName}": pattern "${spec.pattern}" may match dash-leading strings`);
                }
                // Check 8: enum must be non-empty and all strings
                if (spec.enum !== undefined) {
                    if (spec.enum.length === 0) {
                        errors.push(`[ERROR] rule "${id}" param "${paramName}": enum is empty`);
                    }
                    else {
                        const nonStrings = spec.enum.filter((e) => typeof e !== 'string');
                        if (nonStrings.length > 0) {
                            errors.push(`[ERROR] rule "${id}" param "${paramName}": enum contains non-string entries for type:string param`);
                        }
                    }
                }
                // Optional: warn on unsafe regex patterns
                if (spec.pattern !== undefined && UNSAFE_PATTERN_RE.test(spec.pattern)) {
                    errors.push(`[WARN] rule "${id}" param "${paramName}": pattern may contain nested quantifiers (ReDoS risk)`);
                }
            }
        }
    }
    return errors;
}
// ---------------------------------------------------------------------------
// patternRejectsDashLead
// ---------------------------------------------------------------------------
export function patternRejectsDashLead(pattern) {
    // Strip leading anchors
    let stripped = pattern.replace(/^(\^|\\A)/, '');
    // Strip trailing anchors
    stripped = stripped.replace(/(\$|\\Z)$/, '');
    let re;
    try {
        // Re-anchor at start so we test whether the pattern allows a dash-leading match
        re = new RegExp('^' + stripped);
    }
    catch {
        return false;
    }
    // If either '-' or '-' + 32 'a's matches at position 0, pattern allows dash-leading
    if (re.exec('-') !== null || re.exec('-' + 'a'.repeat(32)) !== null) {
        return false;
    }
    return true;
}
