#!/usr/bin/env bash
# Register this repository as a Cursor local plugin (symlink into ~/.cursor/plugins/local/).
#
# Per https://cursor.com/docs/plugins — local testing:
#   ~/.cursor/plugins/local/<plugin-name>  →  plugin root (contains .cursor-plugin/plugin.json)
#
# Usage:
#   ./install-cursor.sh
#
# Then restart Cursor or reload plugins. Slash commands (e.g. /vuln-scan) come from commands/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_NAME="vuln-analysis"
DEST="${HOME}/.cursor/plugins/local/${PLUGIN_NAME}"

mkdir -p "$(dirname "${DEST}")"
ln -sfn "${SCRIPT_DIR}" "${DEST}"

echo "Cursor local plugin registered:"
echo "  ${DEST} -> ${SCRIPT_DIR}"
echo ""
echo "Restart Cursor (or reload window) so the plugin, agents, skills, and commands are picked up."
