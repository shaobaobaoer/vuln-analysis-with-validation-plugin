#!/bin/bash
# env_guard.sh - Environment Guard
#
# Usage (two modes):
#
#   1. Source mode (define functions for subsequent calls):
#      source scripts/env_guard.sh
#      ensure_in_env conda myenv
#      pip install xxx
#
#   2. Standalone check mode:
#      bash scripts/env_guard.sh conda myenv
#      bash scripts/env_guard.sh venv /path/to/venv
#
# Return value: 0=environment correct, 1=environment wrong and repair failed

ensure_in_env() {
    local env_type="$1"   # conda or venv
    local env_id="$2"     # conda env name or venv path

    if [ -z "$env_type" ] || [ -z "$env_id" ]; then
        echo "ensure_in_env: missing parameters (env_type, env_id)"
        return 1
    fi

    if [ "$env_type" = "conda" ]; then
        # Get current activated conda environment
        local current_env
        current_env=$(basename "${CONDA_PREFIX:-}" 2>/dev/null)

        if [ "$current_env" = "$env_id" ]; then
            echo "OK conda:${env_id} | python:$(which python)"
            return 0
        fi

        echo "Environment drift! Current: ${current_env:-base}, expected: $env_id"
        echo "   Reactivating..."
        conda activate "$env_id" 2>/dev/null

        current_env=$(basename "${CONDA_PREFIX:-}" 2>/dev/null)
        if [ "$current_env" = "$env_id" ]; then
            echo "Restored conda:${env_id} | python:$(which python)"
            return 0
        else
            echo "conda activate $env_id failed"
            return 1
        fi

    elif [ "$env_type" = "venv" ]; then
        if [ "$VIRTUAL_ENV" = "$env_id" ]; then
            echo "OK venv:${env_id} | python:$(which python)"
            return 0
        fi

        echo "Environment drift! Current: ${VIRTUAL_ENV:-none}, expected: $env_id"
        echo "   Reactivating..."

        if [ ! -f "${env_id}/bin/activate" ]; then
            echo "venv does not exist: ${env_id}/bin/activate"
            return 1
        fi

        source "${env_id}/bin/activate"
        if [ "$VIRTUAL_ENV" = "$env_id" ]; then
            echo "Restored venv:${env_id} | python:$(which python)"
            return 0
        else
            echo "venv activate failed"
            return 1
        fi
    else
        echo "Unknown environment type: $env_type (should be conda or venv)"
        return 1
    fi
}

# Standalone run mode
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ensure_in_env "$@"
fi
