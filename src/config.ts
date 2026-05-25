import path from 'node:path';
import os from 'node:os';

const HARNESS_DIR = '.ssh_harness';
const DEFAULT_SSH_CONFIG = path.join(os.homedir(), '.ssh', 'config');

export type RuntimeConfig = {
  allowlistPath: string;
  auditPath: string;
  /**
   * Resolved by createServer() via resolveSshConfigPath() with precedence:
   *   1. SSH_HARNESS_CONFIG env (test/operator override)
   *   2. hosts.sshConfigRoot from allowlist.yaml (relative paths resolved against the allowlist's directory)
   *   3. ~/.ssh/config
   * loadConfig() seeds this with the env override or the default; createServer()
   * may overwrite once the allowlist is parsed.
   */
  sshConfigPath: string;
  /** Env override stashed so the server can keep its precedence over allowlist settings. */
  sshConfigEnvOverride?: string;
  auditBestEffort: boolean;
  strictLint: boolean;
  maxRules: number;
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RuntimeConfig {
  const cwdJoin = (...p: string[]) => path.resolve(process.cwd(), HARNESS_DIR, ...p);
  const parsedMaxRules = Number(env.SSH_HARNESS_MAX_RULES ?? 40);
  const envOverride = env.SSH_HARNESS_CONFIG;
  return {
    allowlistPath: env.SSH_HARNESS_ALLOWLIST ?? cwdJoin('allowlist.yaml'),
    auditPath:     env.SSH_HARNESS_AUDIT     ?? cwdJoin('audit.log'),
    // Seed with env override if present, else the global default. createServer
    // can overwrite this with the allowlist's hosts.sshConfigRoot when applicable.
    sshConfigPath: envOverride !== undefined && envOverride !== '' ? envOverride : DEFAULT_SSH_CONFIG,
    sshConfigEnvOverride: envOverride,
    auditBestEffort: env.SSH_HARNESS_AUDIT_BESTEFFORT === '1',
    strictLint:    env.SSH_HARNESS_STRICT_LINT !== '0',
    maxRules:      Number.isFinite(parsedMaxRules) && parsedMaxRules > 0 ? parsedMaxRules : 40,
  };
}

/**
 * Resolve the ssh_config path used at runtime.
 * Precedence: env var > allowlist hosts.sshConfigRoot > ~/.ssh/config.
 * Relative paths in sshConfigRoot are resolved against the allowlist.yaml's directory.
 * Leading "~/" expands to the user's home directory.
 */
export function resolveSshConfigPath(
  envOverride: string | undefined,
  allowlistPath: string,
  allowlistSshConfigRoot: string | undefined,
): string {
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

function expandTilde(p: string): string {
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}
