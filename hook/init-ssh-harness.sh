#!/usr/bin/env bash
# SessionStart hook: ensure .ssh_harness/ exists and is seeded with a default allowlist.yaml.
# Idempotent — never overwrites an existing allowlist.yaml.

set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
HARNESS_DIR="$PROJECT_DIR/.ssh_harness"
ALLOWLIST_FILE="$HARNESS_DIR/allowlist.yaml"

mkdir -p "$HARNESS_DIR"

if [[ -f "$ALLOWLIST_FILE" ]]; then
  exit 0
fi

# Seed content mirrors the server's auto-seed (src/server.ts) so whichever runs
# first on a fresh project writes identical bytes. Default is the SAFE empty
# allowlist (no hosts, no rule tools) — set SSH_HARNESS_SEED_WILDCARD=1 to seed
# read-only diagnostics for every ssh_config host instead.
if [[ "${SSH_HARNESS_SEED_WILDCARD:-}" == "1" ]]; then
  cat > "$ALLOWLIST_FILE" <<'YAML'
# Local allowlist. Edits gated by CODEOWNERS.
# Schema: docs/allowlist-guide.md, README.md
version: 2

hosts:
  allowHosts: &hosts ["*"]                     # ["*"] → expand to every Host alias in ssh_config (excluding `Host *` wildcard).

settings:
  timeoutMs: 30000
  maxStdoutBytes: 262144
  maxStderrBytes: 65536

rules:
  - id: get_uptime
    tool:
      name: ssh_harness_get_uptime
      description: |
        Return how long the host has been up and the current load averages (runs `uptime`).
        Read-only, no arguments. One-shot snapshot.
    params:
      host:
        type: string
        enum: *hosts
        description: Target host alias from the ssh_config above
    template:
      host: "{host}"
      argv: [uptime]

  - id: get_disk_usage
    tool:
      name: ssh_harness_get_disk_usage
      description: |
        Show filesystem disk usage in human-readable form (runs `df -h`).
        Read-only, no arguments. One-shot snapshot.
    params:
      host:
        type: string
        enum: *hosts
    template:
      host: "{host}"
      argv: [df, -h]

  - id: get_process_top
    tool:
      name: ssh_harness_get_process_top
      description: |
        Snapshot all running processes with CPU/memory usage in forest form (runs `ps auxf`).
        Read-only, no arguments. One-shot snapshot.
    params:
      host:
        type: string
        enum: *hosts
    template:
      host: "{host}"
      argv: [ps, auxf]
YAML
  echo "[ssh-harness] seeded wildcard default allowlist at $ALLOWLIST_FILE" >&2
else
  cat > "$ALLOWLIST_FILE" <<'YAML'
# Local allowlist. Edits gated by CODEOWNERS.
# Schema: docs/allowlist-guide.md, README.md
#
# This default is intentionally EMPTY — no SSH rule tools are exposed until you
# opt hosts and rules in. The read-only host-list tool works regardless.
#
# Quick start (enable read-only uptime / df -h / ps auxf for every ssh_config host):
#   1. set:        allowHosts: &hosts ["*"]
#   2. uncomment:  the rules block below
# Or delete this file and re-launch with SSH_HARNESS_SEED_WILDCARD=1.
version: 2

hosts:
  allowHosts: []        # [] = no hosts. ["*"] = every ssh_config Host alias. Or list aliases explicitly.

settings:
  timeoutMs: 30000
  maxStdoutBytes: 262144
  maxStderrBytes: 65536

rules: []
# rules:
#   - id: get_uptime
#     tool: { name: ssh_harness_get_uptime, description: "uptime (read-only)" }
#     params: { host: { type: string, enum: *hosts } }
#     template: { host: "{host}", argv: [uptime] }
#   - id: get_disk_usage
#     tool: { name: ssh_harness_get_disk_usage, description: "df -h (read-only)" }
#     params: { host: { type: string, enum: *hosts } }
#     template: { host: "{host}", argv: [df, -h] }
#   - id: get_process_top
#     tool: { name: ssh_harness_get_process_top, description: "ps auxf (read-only)" }
#     params: { host: { type: string, enum: *hosts } }
#     template: { host: "{host}", argv: [ps, auxf] }
YAML
  echo "[ssh-harness] seeded empty (safe) default allowlist at $ALLOWLIST_FILE" >&2
fi
