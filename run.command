#!/bin/bash
# KeyMelier — macOS launcher
# Double-click this file in Finder, or run from Terminal.
# Handles Homebrew-managed Python (PEP 668) by using a local venv.

set -e
cd "$(dirname "$0")"

VENV_DIR="venv"
PYTHON="$VENV_DIR/bin/python3"
PIP="$VENV_DIR/bin/pip"

# ── Create venv if it doesn't exist yet ─────────────────────────────────────
if [ ! -f "$PYTHON" ]; then
    echo "First run: creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# ── Install / update dependencies inside the venv ───────────────────────────
"$PIP" install -q --upgrade pip
"$PIP" install -q -r requirements.txt

# ── Launch ───────────────────────────────────────────────────────────────────
"$PYTHON" app.py
