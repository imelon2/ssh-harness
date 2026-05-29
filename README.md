# SSH Harness

<p align="center">
  <strong>Harness SSH for your AI — through tools you forge, not commands it types.</strong><br>
  An allowlist-driven Claude Code plugin (MCP server + skills + hooks) for safe SSH diagnostics.<br>
  <em>The LLM cannot type free-form SSH commands.</em><br>
</p>



## Why

Letting an LLM SSH freely into production is dangerous. ssh-harness exposes one MCP tool per allowlist rule — the LLM cannot type free-form SSH commands. Every tool's parameters are typed, validated by Zod (`.strict()`), and substituted into a fixed argv template before `spawnSync` runs the SSH client. No shell ever, no concatenation, no fallbacks.

## Security model

- **Single source of truth**: `.ssh_harness/allowlist.yaml`. Adding a diagnostic is a YAML edit, not a TS change.
- **Fail-closed**: Bad YAML → exit 2. Lint errors → exit 3. Audit append failure → tool call fails (override with `SSH_HARNESS_AUDIT_BESTEFFORT=1`).
- **No shell**: `spawnSync(ssh, [...argv], { shell: false })`. Param values pass through as literal argv elements.
- **Read-only**: Mutation verbs (`rm`, `mv`, `kill`, `restart`, etc.) are an ERROR at startup by default (`SSH_HARNESS_STRICT_LINT` default-on).
- **Auditable**: Every invocation appended as a JSON line to `.ssh_harness/audit.log`. Append failure fails the call.
- **Param constraints**: Every integer param requires `maximum` (prevents adversarial values like `lines=999999999` from exhausting a host). Every string param requires `enum` or `pattern`. Patterns must not match strings starting with `-` (prevents `--remove`-style flag smuggling).

## Install

SSH Harness is a Claude Code plugin. Install it from inside any project's Claude Code session:

```
/plugin marketplace add imelon2/ssh-harness

/plugin install ssh-harness@ssh-harness
```


Restart Claude Code after installing. On the next session the bundled `SessionStart` hook seeds `.ssh_harness/allowlist.yaml` into the current project (never overwriting an existing one), and the MCP server comes up with its tools exposed as `mcp__ssh-harness__ssh_harness_*`.

**Requirements:** Node 24+ on `PATH` (the server runs via `node`). The compiled `bridge/` is committed, so no `npm install` or build step is needed to install.

Then define your hosts and diagnostics in the seeded `.ssh_harness/allowlist.yaml` (see [Adding a new rule](#adding-a-new-rule), [Swapping `localhost` for a real host](#swapping-localhost-for-a-real-host), and [docs/allowlist-guide.md](docs/allowlist-guide.md)).

## Directory layout

```
ssh-harness-1/
├── .mcp.json                    # Claude Code MCP discovery
├── .ssh_harness/
│   ├── allowlist.yaml           # COMMITTED — the security contract
│   ├── ssh_config               # COMMITTED — OpenSSH client config
│   └── audit.log                # gitignored — runtime artifact (0o600)
├── src/                         # TypeScript sources
├── bridge/                      # build output (committed; policy)
├── examples/
│   └── allowlist.yaml           # reference template
├── tests/
├── package.json
├── tsconfig.json
└── CODEOWNERS                   # pins .ssh_harness/ to security-ops
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SSH_HARNESS_ALLOWLIST` | `<cwd>/.ssh_harness/allowlist.yaml` | Path to allowlist YAML |
| `SSH_HARNESS_CONFIG` | (see below) | Path to OpenSSH client config. Overrides `hosts.sshConfigRoot` in the allowlist. Unset → allowlist field → `~/.ssh/config` |
| `SSH_HARNESS_AUDIT` | `<cwd>/.ssh_harness/audit.log` | Path to audit log |
| `SSH_HARNESS_AUDIT_BESTEFFORT` | unset (fail-closed) | Set to `1` to make audit append failure non-fatal |
| `SSH_HARNESS_STRICT_LINT` | `1` (on) | Set to `0` to demote mutation-verb lint to WARN and skip host-alias drift exit |
| `SSH_HARNESS_MAX_RULES` | `40` | Lint cap; raise for large allowlists |

ssh_config path resolution precedence (highest first):
1. `SSH_HARNESS_CONFIG` env (test/operator override)
2. `hosts.sshConfigRoot` in the allowlist (relative paths resolve against the allowlist file's directory; leading `~/` expands)
3. `~/.ssh/config`

Tunables for ssh execution (timeout, stdout/stderr caps, ssh binary path, identity file) live in the allowlist YAML's `settings:` block, not env. Single source of truth.

## Run

### As a Claude Code MCP server (recommended)

`.mcp.json` ships with this repo. Open the project in Claude Code:

```bash
cd ssh-harness-1
claude
```

Claude Code auto-discovers `.mcp.json` and connects. Tools appear in the LLM's tool list as `mcp__ssh-harness__ssh_harness_get_uptime`, `mcp__ssh-harness__ssh_harness_get_disk_usage`, etc.

### Standalone (for debugging)

```bash
npm start
```

Reads `<cwd>/.ssh_harness/{allowlist.yaml, ssh_config}` and serves MCP over stdio. Send `SIGINT` (`Ctrl-C`) to shut down.

### With the MCP Inspector

Verify tool registration and protocol behavior with the official inspector (pinned version):

```bash
npx @modelcontextprotocol/inspector@latest node bridge/server.js
```

5-step checklist:

1. Inspector UI opens in the browser; the `ssh-harness` server appears as **connected**.
2. Tools tab lists the rules in your allowlist (3 in the seed: `ssh_harness_get_uptime`, `ssh_harness_get_disk_usage`, `ssh_harness_get_process_top`) **plus** the always-on built-in `ssh_harness_get_allow_host_lists`.
3. Click `ssh_harness_get_uptime`, fill `host: localhost`, click **Call Tool**.
4. If your machine has ssh-to-localhost configured, you should see uptime output. If not, you'll see an MCP error referencing the ssh exit code or connection refusal — that proves the pipeline reached `spawnSync` cleanly.
5. Open `.ssh_harness/audit.log`. Each invocation has a JSON-line entry with `outcome`, `ruleId`, `params`, `argv`, `durationMs`, `stdoutTail`.

## Built-in tools

These tools ship with the server and are **not defined in `allowlist.yaml`**. They are always present regardless of allowlist contents and are audited just like rule-derived tools (with `ruleId: "builtin:..."`).

### `ssh_harness_get_allow_host_lists`

Return the list of SSH host aliases the MCP is allowed to reach (sourced from `allowlist.yaml` → `hosts.allowHosts`). Optionally opens a short SSH connection per host to verify reachability.

- **Input schema** (strict — extra keys are rejected):
  ```json
  { "checkHealth": false }    // optional, default false
  ```
- **Output when `checkHealth` is false (or omitted)**:
  ```json
  {
    "hosts": ["alpha", "beta"],
    "sshConfigPath": "/path/to/ssh_config",
    "checked": false
  }
  ```
- **Output when `checkHealth: true`** (runs `ssh ... -- true` once per host, `ConnectTimeout=5s`, per-host timeout 7s):
  ```json
  {
    "hosts": ["alpha", "beta"],
    "sshConfigPath": "/path/to/ssh_config",
    "checked": true,
    "results": [
      { "host": "alpha", "reachable": true,  "exitCode": 0,   "durationMs": 113, "timedOut": false },
      { "host": "beta",  "reachable": false, "exitCode": 255, "durationMs": 5042, "timedOut": false, "error": "connection refused" }
    ],
    "summary": { "total": 2, "reachable": 1, "unreachable": 1 }
  }
  ```

**Cost note.** `checkHealth: true` makes one SSH connection per allow-listed host serially. With N hosts and default settings, worst-case latency is `N * 7s`. Prefer `checkHealth: false` for routine catalog browsing; reserve `true` for explicit connectivity probes.

**Privacy note.** Only host aliases and the resolved `ssh_config` path are returned. Underlying `HostName` / IPs from `ssh_config` are not exposed to the tool caller.

**Collisions.** Defining an allowlist rule whose `tool.name` equals `ssh_harness_get_allow_host_lists` is rejected at startup (exit code 3).

## Allowlist schema reference

The allowlist is YAML. Top-level fields:

- `version: 2` — required, must literally be `2`.
- `hosts:` — object with two fields:
  - `allowHosts: [...]` — non-empty array of strings. Conventionally given a YAML anchor (`&hosts`) for re-use in `enum: *hosts`. Special value `["*"]` expands at startup to every `Host` alias declared in the resolved `ssh_config` (the `Host *` catch-all is ignored, and the same expansion is applied to any rule param whose `enum` is also `["*"]`). Expansion fails with exit 3 if the ssh_config has zero usable aliases.
  - `sshConfigRoot: <path>` — optional. Path to the OpenSSH client config. Relative paths resolve against this YAML file's directory; leading `~/` expands to home. Omit to default to `~/.ssh/config`. `SSH_HARNESS_CONFIG` env always wins.
- `settings:` — optional. Tunables. Defaults:
  - `timeoutMs: 30000`
  - `maxStdoutBytes: 262144` — set to `0` to disable the cap (no truncation; `maxBuffer` becomes `Infinity`)
  - `maxStderrBytes: 65536` — set to `0` to disable the cap
  - `sshBin: /usr/bin/ssh`
  - `identityFile:` (unset; ssh picks from `IdentityFile` in the resolved ssh_config)
- `rules: [...]` — array of rule objects. Cap: 40 (override with `SSH_HARNESS_MAX_RULES`).

Each rule:

```yaml
- id: <unique_snake_case_id>
  tool:
    name: ssh_<lowercase_underscore_name>   # /^[a-z][a-z0-9_]{0,63}$/
    description: |
      Multi-line description shown to the LLM. State what it does and
      when to use it.
  params:
    <param_name>:
      type: string | integer
      enum: [a, b, c]                # string: required if no pattern
      pattern: '^[a-z]+$'             # string: required if no enum; must NOT match leading '-'
      minimum: 0                      # integer: optional
      maximum: 1000                   # integer: REQUIRED
      default: <value>                # optional
      description: <text>             # optional
      secret: true                    # optional; redacts value in audit log
  template:
    host: "{host}"                    # placeholder resolved from params
    argv: [<literal>, "{param}", ...] # each entry: literal or {placeholder}
```

## Adding a new rule

1. Edit `.ssh_harness/allowlist.yaml`. Add one rule object.
2. Make sure:
   - `id` is unique
   - `tool.name` is `ssh_*` snake_case
   - `argv[0]` is a read-only command (`docker`, `journalctl`, `tail`, `df`, `ps`, `systemctl status`, etc.)
   - Every `{placeholder}` in `template` maps to a key in `params`
   - Every string param has `enum` or `pattern`
   - Every integer param has `maximum`
3. Run `npm test` — Phase 6's `tests/server.integration.test.ts` and Phase 1's lint will catch most schema mistakes.
4. Restart the MCP server. (Hot-reload is Phase 8 / future work.)

CODEOWNERS gates edits to `.ssh_harness/` to security-ops on GitHub/GitLab. On other platforms, enforce manually.

## Swapping `localhost` for a real host

The shipped `.ssh_harness/{allowlist.yaml, ssh_config}` target `localhost`. To use real hosts:

1. Edit the ssh_config file referenced by `hosts.sshConfigRoot` (defaults to `.ssh_harness/ssh_config` in the seed; falls back to `~/.ssh/config` if you remove `sshConfigRoot`). Add Host blocks:
   ```sshconfig
   Host prod-api
       HostName api.example.com
       User llm-diag
       IdentityFile ~/.ssh/id_ed25519_llm_diag
       StrictHostKeyChecking accept-new
   ```
2. Edit `.ssh_harness/allowlist.yaml`. Replace `hosts.allowHosts: [localhost]` with `[prod-api]` (or extend the list). If you want to read from a different ssh_config, set `hosts.sshConfigRoot` to its path (relative to the YAML file, or absolute, or `~/...`).
3. Restart the server. The startup banner shows the resolved paths and rule count.

## Audit log rotation

`audit.log` is append-only JSON-lines. Rotate via standard tooling:

```bash
# Daily rotation example with logrotate
.ssh_harness/audit.log {
    daily
    rotate 14
    compress
    missingok
    create 0600 you you
    postrotate
        # nothing — server appends in-place; logrotate handles via copytruncate alternative if needed
    endscript
}
```

For high-volume use, route to syslog/journald via a wrapper that tails the file.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server exits with code 2 | YAML parse error | Check `.ssh_harness/allowlist.yaml` syntax with `npx yaml lint .ssh_harness/allowlist.yaml` or any YAML linter |
| Server exits with code 3 | Lint error or host-alias drift | Read stderr; fix the rule or `ssh_config` Host declaration; if drift is intentional, set `SSH_HARNESS_STRICT_LINT=0` (downgrades to WARN) |
| Tool call returns `audit append failed` | Disk full, permission denied on `.ssh_harness/audit.log` | Fix filesystem, or temporarily set `SSH_HARNESS_AUDIT_BESTEFFORT=1` (audit failures become stderr warnings) |
| Tool call returns `schema error` | LLM passed an invalid param value | The LLM should self-correct; check the audit log entry for what was sent |
| Tool call hangs | ssh waiting for input or timeout exceeded | All rules run with `BatchMode=yes`, `ConnectTimeout=5`, and `settings.timeoutMs`; reduce timeout or check `ssh_config` |
| `mcp__ssh-harness__*` tools don't appear in Claude Code | `.mcp.json` not detected or build missing | Run `npm install && npm run build` in the repo root before starting Claude Code |

## Known limitations

- **ANSI / control-character injection from remote stdout**: ssh-harness does not strip ANSI escape sequences or C0 control characters from stdout/stderr before returning to the LLM. A compromised remote service writing terminal escape sequences could spoof rendering in MCP clients that render output as a terminal. Treat remote stdout as untrusted text. Future work: configurable stripping.
- **SIGPIPE handling**: If the MCP client (e.g., Claude Code) terminates mid-call, the server may receive SIGPIPE during stdout write. Currently not explicitly trapped; relies on Node's default. Acceptable for v1; revisit if seen in practice.
- **CODEOWNERS portability**: `CODEOWNERS` only enforces gated review on platforms that support it (GitHub, GitLab). On other platforms / local-only repos, the operator must enforce allowlist review manually.

## Future work

- **Hot-reload** of `allowlist.yaml` without restart (Phase 8 in the plan — deferred).
- **ANSI/control-char stripping** before relaying stdout/stderr to the LLM.
- **`ControlMaster` / `ControlPersist`** for SSH connection reuse (LLM-loop workflows currently pay 300ms+ per call for handshakes).
- **Remote audit shipping** (syslog forwarder, Loki/Splunk push).
- **Per-rule rate limits / cooldowns** to prevent loop-induced host hammering.

## License

(specify your license here)

## Plan & ADR

The full implementation plan and Architecture Decision Record live at `.omc/plans/ssh-harness-initial.md`.
