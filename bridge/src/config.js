import path from 'node:path';
import os from 'node:os';
const HARNESS_DIR = '.ssh_harness';
const DEFAULT_SSH_CONFIG = path.join(os.homedir(), '.ssh', 'config');
export function loadConfig(env = process.env) {
    const cwdJoin = (...p) => path.resolve(process.cwd(), HARNESS_DIR, ...p);
    const parsedMaxRules = Number(env.SSH_HARNESS_MAX_RULES ?? 40);
    const envOverride = env.SSH_HARNESS_CONFIG;
    return {
        allowlistPath: env.SSH_HARNESS_ALLOWLIST ?? cwdJoin('allowlist.yaml'),
        auditPath: env.SSH_HARNESS_AUDIT ?? cwdJoin('audit.log'),
        // Seed with env override if present, else the global default. createServer
        // can overwrite this with the allowlist's hosts.sshConfigRoot when applicable.
        sshConfigPath: envOverride !== undefined && envOverride !== '' ? envOverride : DEFAULT_SSH_CONFIG,
        sshConfigEnvOverride: envOverride,
        auditBestEffort: env.SSH_HARNESS_AUDIT_BESTEFFORT === '1',
        strictLint: env.SSH_HARNESS_STRICT_LINT !== '0',
        maxRules: Number.isFinite(parsedMaxRules) && parsedMaxRules > 0 ? parsedMaxRules : 40,
    };
}
/**
 * Resolve the ssh_config path used at runtime.
 * Precedence: env var > allowlist hosts.sshConfigRoot > ~/.ssh/config.
 * Relative paths in sshConfigRoot are resolved against the allowlist.yaml's directory.
 * Leading "~/" expands to the user's home directory.
 */
export function resolveSshConfigPath(envOverride, allowlistPath, allowlistSshConfigRoot) {
    if (envOverride !== undefined && envOverride !== '') {
        return envOverride;
    }
    if (allowlistSshConfigRoot !== undefined && allowlistSshConfigRoot !== '') {
        // Tilde must expand BEFORE absoluteness check, otherwise "~/..." is treated
        // as a relative path and gets joined with the allowlist directory.
        const expanded = expandTilde(allowlistSshConfigRoot);
        return path.isAbsolute(expanded)
            ? expanded
            : path.resolve(path.dirname(allowlistPath), expanded);
    }
    return DEFAULT_SSH_CONFIG;
}
function expandTilde(p) {
    if (p === '~')
        return os.homedir();
    if (p.startsWith('~/'))
        return path.join(os.homedir(), p.slice(2));
    return p;
}
