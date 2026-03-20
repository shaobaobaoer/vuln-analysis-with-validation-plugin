#!/usr/bin/env bash
# Install vuln-analysis plugin for Qoder
#
# Usage:
#   ./install-qoder.sh           # global: ~/.qoder/
#   ./install-qoder.sh --local   # local:  ./.qoder/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "--local" ]; then
DEST="$(pwd)/.qoder"
MODE="local"
else
DEST="${HOME}/.qoder"
MODE="global"
fi

echo "[${MODE}] Installing vuln-analysis to ${DEST} ..."

mkdir -p "${DEST}"

# Core structure
for dir in commands agents skills; do
if [ -d "${SCRIPT_DIR}/${dir}" ]; then
mkdir -p "${DEST}/${dir}"
cp -r "${SCRIPT_DIR}/${dir}/"* "${DEST}/${dir}/"
fi
done

# Make scripts executable
find "${DEST}" -name "*.sh" -exec chmod +x {} \;
[ -f "${DEST}/skills/validation-framework/resources/trigger.linux" ] && chmod +x "${DEST}/skills/validation-framework/resources/trigger.linux"

echo "Done! Plugin installed to ${DEST}"
echo "Directories populated:"
echo "  ${DEST}/commands/"
echo "  ${DEST}/agents/"
echo "  ${DEST}/skills/"
echo "Usage:  /vuln-scan <github_repo_url>"

