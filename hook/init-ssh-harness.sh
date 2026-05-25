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

cat > "$ALLOWLIST_FILE" <<'YAML'
# Local allowlist. Edits gated by CODEOWNERS.
# Schema: docs/allowlist-guide.md, README.md
version: 2

hosts:
  allowHosts: &hosts ["*"]                     # ["*"] → expand to every Host alias in ssh_config (excluding `Host *` wildcard).
                                               # Or list aliases explicitly: ["k8s-master", "web-1"].
  # sshConfigRoot: "./ssh_config"                # relative to this file's directory (.ssh_harness/).
                                               # Omit to fall back to ~/.ssh/config.

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
        Use when: confirming the host is reachable or estimating boot-age and load before deeper checks.
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
        Use when: diagnosing disk pressure, out-of-space conditions, or auditing mount points — not for CPU/memory consumers.
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
        Use when: identifying runaway processes or unexpected CPU/memory consumers — not for disk or storage checks.
    params:
      host:
        type: string
        enum: *hosts
    template:
      host: "{host}"
      argv: [ps, auxf]
YAML

echo "[ssh-harness] seeded default allowlist at $ALLOWLIST_FILE" >&2
