#!/bin/bash
# setup_python_env.sh - Create and Configure Python Environment
#
# Usage:
#   bash scripts/setup_python_env.sh --type conda --name myenv --project /path/to/project [--yml environment.yml] [--python 3.10]
#   bash scripts/setup_python_env.sh --type venv  --path /path/to/venv --project /path/to/project
#
# Features:
#   1. Create conda/venv environment
#   2. Install dependencies (requirements.txt / pyproject.toml / setup.py / Pipfile)
#   3. Automatically verify environment before each installation step
#
# Does NOT:
#   - Install ML/GPU packages (handled by install_ml_deps.sh)
#   - Run database migrations (determined by agent based on framework)
#   - Start the application
#
# Return value: 0=success, 1=failure
# Final output: ENV_READY=<conda:name|venv:path>

set -e

# ── Argument parsing ──

ENV_TYPE=""
ENV_NAME=""
VENV_PATH=""
PROJECT_DIR=""
YML_FILE=""
PYTHON_VER="3.10"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --type)    ENV_TYPE="$2";    shift 2 ;;
        --name)    ENV_NAME="$2";    shift 2 ;;
        --path)    VENV_PATH="$2";   shift 2 ;;
        --project) PROJECT_DIR="$2"; shift 2 ;;
        --yml)     YML_FILE="$2";    shift 2 ;;
        --python)  PYTHON_VER="$2";  shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ -z "$PROJECT_DIR" ]; then
    echo "--project is required"
    exit 1
fi

# ── Load environment guard ──

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/env_guard.sh"

# ── Helper functions ──

guard() {
    if [ "$ENV_TYPE" = "conda" ]; then
        ensure_in_env conda "$ENV_NAME" || { echo "Environment lost, aborting"; exit 1; }
    elif [ "$ENV_TYPE" = "venv" ]; then
        ensure_in_env venv "$VENV_PATH" || { echo "Environment lost, aborting"; exit 1; }
    fi
}

install_pip_deps() {
    guard
    cd "$PROJECT_DIR"

    if [ -f requirements.txt ]; then
        echo "pip install -r requirements.txt"
        pip install -r requirements.txt
    elif [ -f pyproject.toml ]; then
        echo "pip install -e . (pyproject.toml)"
        pip install -e .
    elif [ -f setup.py ]; then
        echo "pip install -e . (setup.py)"
        pip install -e .
    elif [ -f Pipfile ]; then
        echo "pipenv install"
        pip install pipenv && pipenv install --system
    else
        echo "No Python dependency file found"
    fi
}

# ── Create environment ──

cd "$PROJECT_DIR"

if [ "$ENV_TYPE" = "conda" ]; then

    if [ -z "$ENV_NAME" ]; then
        echo "--name is required for conda mode"
        exit 1
    fi

    # Auto-detect python version
    if [ -f .python-version ]; then
        PYTHON_VER=$(head -1 .python-version | tr -d '[:space:]')
        echo "Read from .python-version: Python ${PYTHON_VER}"
    fi

    if [ -n "$YML_FILE" ] && [ -f "$YML_FILE" ]; then
        # Create from yml
        echo "conda env create -f ${YML_FILE} -n ${ENV_NAME}"
        echo "   This may take 5-15 minutes..."
        conda env remove -n "$ENV_NAME" -y 2>/dev/null || true
        conda env create -f "$YML_FILE" -n "$ENV_NAME"
    else
        # Empty environment
        echo "conda create -n ${ENV_NAME} python=${PYTHON_VER}"
        conda env remove -n "$ENV_NAME" -y 2>/dev/null || true
        conda create -n "$ENV_NAME" python="${PYTHON_VER}" -y
    fi

    conda activate "$ENV_NAME"
    guard

    # yml may not include all pip dependencies
    install_pip_deps

elif [ "$ENV_TYPE" = "venv" ]; then

    if [ -z "$VENV_PATH" ]; then
        VENV_PATH="${PROJECT_DIR}/venv"
    fi

    echo "python3 -m venv ${VENV_PATH}"
    python3 -m venv "$VENV_PATH"
    source "${VENV_PATH}/bin/activate"
    guard

    pip install --upgrade pip
    guard

    install_pip_deps

else
    echo "--type must be conda or venv"
    exit 1
fi

# ── Done ──

guard
echo ""
echo "Python environment ready"
python --version
echo "   pip packages: $(pip list --format=columns 2>/dev/null | wc -l) installed"

if [ "$ENV_TYPE" = "conda" ]; then
    echo "ENV_READY=conda:${ENV_NAME}"
else
    echo "ENV_READY=venv:${VENV_PATH}"
fi
