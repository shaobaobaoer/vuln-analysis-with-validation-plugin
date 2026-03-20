#!/bin/bash
# install_conda.sh - Install Miniforge (conda)
#
# Usage:
#   bash scripts/install_conda.sh [install_path]
#
# Default install location: ~/miniforge3
# Available in current shell after install (does not modify .bashrc)
#
# Return value: 0=success, 1=failure
# Output: Last line is CONDA_PATH=<path> (for caller to eval)

set -e

INSTALL_DIR="${1:-$HOME/miniforge3}"
ARCH=$(uname -m)
OS=$(uname -s)

echo "Installing Miniforge -> ${INSTALL_DIR}"
echo "   Estimated time: 2-5 minutes..."

# ── Download ──

INSTALLER="/tmp/miniforge_installer_$$.sh"

PRIMARY_URL="https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-${OS}-${ARCH}.sh"
MIRROR_URL="https://mirrors.tuna.tsinghua.edu.cn/github-release/conda-forge/miniforge/LatestRelease/Miniforge3-${OS}-${ARCH}.sh"

download_ok=false
for url in "$PRIMARY_URL" "$MIRROR_URL"; do
    echo "   Trying: $url"
    if curl -fSL --connect-timeout 10 --max-time 300 -o "$INSTALLER" "$url" 2>&1; then
        download_ok=true
        break
    fi
done

if [ "$download_ok" = "false" ]; then
    echo "Miniforge download failed"
    rm -f "$INSTALLER"
    exit 1
fi

# ── Install ──

bash "$INSTALLER" -b -p "$INSTALL_DIR"
rm -f "$INSTALLER"

# ── Initialize (current shell) ──

eval "$("${INSTALL_DIR}/bin/conda" shell.bash hook)"

# ── Configure mirrors ──

conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main/
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge/
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/pytorch/
conda config --set show_channel_urls yes

echo "Miniforge installation complete: $(conda --version)"
echo "CONDA_PATH=${INSTALL_DIR}"
