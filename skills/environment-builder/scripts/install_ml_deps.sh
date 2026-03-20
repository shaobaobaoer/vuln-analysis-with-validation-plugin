#!/bin/bash
# install_ml_deps.sh - Install ML/AI Dependencies (PyTorch / TensorFlow)
#
# Usage:
#   bash scripts/install_ml_deps.sh --type conda --name myenv --project /path/to/project
#   bash scripts/install_ml_deps.sh --type venv  --path /path/to/venv --project /path/to/project
#
# Behavior:
#   1. Detect GPU and CUDA version
#   2. Detect whether the project needs torch or tensorflow
#   3. GPU present -> only install GPU version, output GPU_INSTALL_FAILED on failure for agent to ask user
#   4. No GPU -> output NO_GPU_DETECTED for agent to ask user
#   5. Verify CUDA availability after installation
#
# Will NOT auto-downgrade to CPU version! Downgrade requires user confirmation.
#
# Return values:
#   0 = GPU version installed successfully and verified
#   1 = User intervention needed (check last line of stdout for status code)
#
# Status codes (last line of stdout):
#   ML_GPU_OK              - GPU version installed successfully
#   ML_NO_GPU              - No GPU detected, user confirmation needed to install CPU version
#   ML_GPU_INSTALL_FAILED  - GPU version installation failed, user confirmation needed for CPU downgrade
#   ML_GPU_VERIFY_FAILED   - Installed but CUDA unavailable, user confirmation needed
#   ML_NO_ML_DEPS          - Project does not need ML dependencies

set -e

# ── Argument parsing ──

ENV_TYPE=""
ENV_NAME=""
VENV_PATH=""
PROJECT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --type)    ENV_TYPE="$2";    shift 2 ;;
        --name)    ENV_NAME="$2";    shift 2 ;;
        --path)    VENV_PATH="$2";   shift 2 ;;
        --project) PROJECT_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/env_guard.sh"

guard() {
    if [ "$ENV_TYPE" = "conda" ]; then
        ensure_in_env conda "$ENV_NAME" || exit 1
    else
        ensure_in_env venv "$VENV_PATH" || exit 1
    fi
}

cd "$PROJECT_DIR"

# ── Detect what the project needs ──

NEEDS_TORCH=false
NEEDS_TF=false

grep -qi "torch\|torchvision" requirements*.txt pyproject.toml setup.py 2>/dev/null && NEEDS_TORCH=true
grep -qi "tensorflow" requirements*.txt pyproject.toml setup.py 2>/dev/null && NEEDS_TF=true

if [ "$NEEDS_TORCH" = "false" ] && [ "$NEEDS_TF" = "false" ]; then
    echo "Project does not need PyTorch/TensorFlow"
    echo "ML_NO_ML_DEPS"
    exit 0
fi

echo "ML dependencies detected: torch=${NEEDS_TORCH} tensorflow=${NEEDS_TF}"

# ── Detect GPU ──

if ! nvidia-smi >/dev/null 2>&1; then
    echo ""
    echo "No GPU detected (nvidia-smi unavailable)"
    echo "   This project depends on ML frameworks; training/inference will be very slow without GPU."
    echo ""
    echo "   Possible scenarios:"
    echo "   1. No GPU available -> need your confirmation to install CPU version"
    echo "   2. GPU exists but driver not installed -> install NVIDIA driver first"
    echo ""
    echo "ML_NO_GPU"
    exit 1
fi

# ── GPU present ──

CUDA_VERSION=$(nvidia-smi | grep -oP 'CUDA Version: \K[\d.]+' | cut -d. -f1-2)
GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)
GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)

echo ""
echo "GPU: ${GPU_NAME} (${GPU_MEM}MiB)"
echo "   CUDA: ${CUDA_VERSION}"
echo "   Installing GPU version..."
echo ""

guard

# ── PyTorch GPU ──

if [ "$NEEDS_TORCH" = "true" ]; then
    echo "Installing PyTorch GPU (CUDA ${CUDA_VERSION})..."
    guard

    if [ "$ENV_TYPE" = "conda" ]; then
        if ! conda install pytorch torchvision torchaudio pytorch-cuda="${CUDA_VERSION}" -c pytorch -c nvidia -y 2>&1; then
            echo ""
            echo "PyTorch GPU version installation failed (CUDA ${CUDA_VERSION})"
            echo "   Possible cause: CUDA version incompatible / conda source missing corresponding version"
            echo "ML_GPU_INSTALL_FAILED:torch:cuda${CUDA_VERSION}"
            exit 1
        fi
    else
        # venv uses pip
        if ! pip install torch torchvision torchaudio --index-url "https://download.pytorch.org/whl/cu${CUDA_VERSION//./}" 2>&1; then
            echo ""
            echo "PyTorch GPU pip installation failed"
            echo "ML_GPU_INSTALL_FAILED:torch:cuda${CUDA_VERSION}"
            exit 1
        fi
    fi

    # Verify
    guard
    echo "Verifying PyTorch CUDA..."
    GPU_CHECK=$(python -c "import torch; print(torch.cuda.is_available())" 2>/dev/null || echo "Error")

    if [ "$GPU_CHECK" = "True" ]; then
        VRAM=$(python -c "import torch; print(f'{torch.cuda.get_device_properties(0).total_mem/1024**3:.1f}GB')" 2>/dev/null)
        echo "  PyTorch CUDA available (VRAM ${VRAM})"
    else
        echo "  PyTorch installed but torch.cuda.is_available()=False"
        echo "  Possible CUDA toolkit version mismatch with driver"
        echo "ML_GPU_VERIFY_FAILED:torch"
        exit 1
    fi
fi

# ── TensorFlow GPU ──

if [ "$NEEDS_TF" = "true" ]; then
    echo "Installing TensorFlow GPU..."
    guard

    if [ "$ENV_TYPE" = "conda" ]; then
        if ! conda install tensorflow-gpu -y 2>&1; then
            echo "TensorFlow GPU version installation failed"
            echo "ML_GPU_INSTALL_FAILED:tensorflow:cuda${CUDA_VERSION}"
            exit 1
        fi
    else
        if ! pip install tensorflow 2>&1; then
            echo "TensorFlow installation failed"
            echo "ML_GPU_INSTALL_FAILED:tensorflow:cuda${CUDA_VERSION}"
            exit 1
        fi
    fi

    # Verify
    guard
    echo "Verifying TensorFlow GPU..."
    TF_GPUS=$(python -c "import tensorflow as tf; print(len(tf.config.list_physical_devices('GPU')))" 2>/dev/null || echo "0")

    if [ "$TF_GPUS" -gt 0 ] 2>/dev/null; then
        echo "  TensorFlow detected ${TF_GPUS} GPU(s)"
    else
        echo "  TensorFlow did not detect any GPU"
        echo "ML_GPU_VERIFY_FAILED:tensorflow"
        exit 1
    fi
fi

echo ""
echo "ML GPU dependency installation complete"
echo "ML_GPU_OK"
