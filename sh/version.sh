#!/usr/bin/env bash
set -euo pipefail

# Bulk-apply a semver version across:
#   - package.json                            (.version)
#   - .claude-plugin/plugin.json              (.version)
#   - .claude-plugin/marketplace.json         (.version AND .plugins[0].version)
#
# Usage:
#   sh/version.sh "1.1.1"     # set all to 1.1.1
#   sh/version.sh             # bump lowest patch by 1 and unify

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PKG_JSON="$ROOT_DIR/package.json"
PLUGIN_JSON="$ROOT_DIR/.claude-plugin/plugin.json"
MARKETPLACE_JSON="$ROOT_DIR/.claude-plugin/marketplace.json"

usage() {
  cat <<EOF
Usage: $(basename "$0") [version]

Apply a version across:
  - package.json (.version)
  - .claude-plugin/plugin.json (.version)
  - .claude-plugin/marketplace.json (.version and .plugins[0].version)

If [version] is omitted, the lowest version found across these fields is
incremented by 1 patch (e.g. 1.0.0 -> 1.0.1) and applied uniformly.

Examples:
  $(basename "$0") 1.1.1     # set all to 1.1.1
  $(basename "$0")           # bump lowest patch
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed." >&2
  exit 1
fi

for f in "$PKG_JSON" "$PLUGIN_JSON" "$MARKETPLACE_JSON"; do
  if [[ ! -f "$f" ]]; then
    echo "Error: missing file: $f" >&2
    exit 1
  fi
done

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
  V_PKG=$(jq -r '.version' "$PKG_JSON")
  V_PLUGIN=$(jq -r '.version' "$PLUGIN_JSON")
  V_MARKET_ROOT=$(jq -r '.version' "$MARKETPLACE_JSON")
  V_MARKET_PLUGIN=$(jq -r '.plugins[0].version' "$MARKETPLACE_JSON")

  echo "Current versions:"
  echo "  package.json                    : $V_PKG"
  echo "  .claude-plugin/plugin.json      : $V_PLUGIN"
  echo "  .claude-plugin/marketplace.json : $V_MARKET_ROOT (root) / $V_MARKET_PLUGIN (plugins[0])"

  LOWEST=$(printf '%s\n' "$V_PKG" "$V_PLUGIN" "$V_MARKET_ROOT" "$V_MARKET_PLUGIN" | sort -V | head -n1)

  if ! [[ "$LOWEST" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "Error: cannot parse lowest version as X.Y.Z: $LOWEST" >&2
    exit 1
  fi
  MAJOR="${BASH_REMATCH[1]}"
  MINOR="${BASH_REMATCH[2]}"
  PATCH="${BASH_REMATCH[3]}"
  PATCH=$((PATCH + 1))
  TARGET="$MAJOR.$MINOR.$PATCH"

  echo "Lowest: $LOWEST -> bumping patch to $TARGET"
fi

if ! [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must match X.Y.Z, got: $TARGET" >&2
  exit 1
fi

apply_jq() {
  local file="$1"
  shift
  local tmp
  tmp=$(mktemp)
  jq "$@" "$file" > "$tmp"
  mv "$tmp" "$file"
}

apply_jq "$PKG_JSON"         --arg v "$TARGET" '.version = $v'
apply_jq "$PLUGIN_JSON"      --arg v "$TARGET" '.version = $v'
apply_jq "$MARKETPLACE_JSON" --arg v "$TARGET" '.version = $v | .plugins[0].version = $v'

echo "Applied version $TARGET to:"
echo "  - package.json"
echo "  - .claude-plugin/plugin.json"
echo "  - .claude-plugin/marketplace.json (root + plugins[0])"
