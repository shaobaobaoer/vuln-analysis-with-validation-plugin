#!/usr/bin/env bash
# Install vuln-analysis plugin for Claude Code
#
# Usage:
#   ./install-claude.sh           # global: ~/.claude/plugins/vuln-analysis/
#   ./install-claude.sh --local   # local:  ./.claude/plugins/vuln-analysis/
set -euo pipefail

PLUGIN_NAME="vuln-analysis"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "--local" ]; then
    DEST="$(pwd)/.claude/plugins/${PLUGIN_NAME}"
    MODE="local"
else
    DEST="${HOME}/.claude/plugins/${PLUGIN_NAME}"
    MODE="global"
fi

echo "[${MODE}] Installing ${PLUGIN_NAME} to ${DEST} ..."

mkdir -p "${DEST}"

# Core plugin structure
for dir in .claude-plugin commands agents skills core tools examples memory .claude; do
    if [ -d "${SCRIPT_DIR}/${dir}" ]; then
        rm -rf "${DEST}/${dir}"
        cp -r "${SCRIPT_DIR}/${dir}" "${DEST}/${dir}"
    fi
done

# Copy top-level files
for f in README.md requirements.txt claude.sh; do
    if [ -f "${SCRIPT_DIR}/${f}" ]; then
        cp "${SCRIPT_DIR}/${f}" "${DEST}/${f}"
    fi
done

# Make scripts executable
find "${DEST}" -name "*.sh" -exec chmod +x {} \;
[ -f "${DEST}/skills/_shared/trigger.linux" ] && chmod +x "${DEST}/skills/_shared/trigger.linux"

echo "Done! Plugin installed to ${DEST}"
echo "Verify: ls ${DEST}/.claude-plugin/plugin.json"
echo "Usage:  /vuln-scan <github_repo_url>"
