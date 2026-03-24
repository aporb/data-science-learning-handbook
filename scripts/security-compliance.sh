#!/bin/bash
# Security compliance scan stub
# Runs flake8 (style/error checks) and bandit (security linting) on the project

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================"
echo "Security Compliance Scan"
echo "Started: $(date)"
echo "Project root: $PROJECT_ROOT"
echo "============================================"

cd "$PROJECT_ROOT"

# Install tools if not present
echo ""
echo "[1/2] Installing scan dependencies..."
python -m pip install --quiet flake8 bandit 2>/dev/null || true

# flake8 — style and error checks
echo ""
echo "[2/2] Running flake8..."
if command -v flake8 &>/dev/null; then
    flake8 . \
        --count \
        --select=E9,F63,F7,F82 \
        --show-source \
        --statistics \
        --exclude=.git,__pycache__,.tox,.eggs,*.egg,node_modules \
        || { echo "flake8 found critical issues (exit $?)"; exit 1; }
    echo "flake8 passed."
else
    echo "WARNING: flake8 not available, skipping."
fi

# bandit — Python security linter
echo ""
echo "[3/3] Running bandit..."
if command -v bandit &>/dev/null; then
    bandit -r . \
        --exclude ./.git,./node_modules,./.tox \
        -ll \
        -q \
        || { echo "bandit found security issues (exit $?)"; exit 1; }
    echo "bandit passed."
else
    echo "WARNING: bandit not available, skipping."
fi

echo ""
echo "============================================"
echo "Security compliance scan complete: $(date)"
echo "============================================"
