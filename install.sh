#!/bin/sh
# OpenLine Living Projects installer (developer preview).
# Creates .venv, installs only cryptography, verifies the manifest.
# Exits non-zero on any failure. Do not edit files to make it pass.
set -eu
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "install: python3 not found (need Python 3.11+)" >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "install: git not found" >&2
  exit 1
fi
PYVER=$(python3 -c 'import sys; print(sys.version_info.major, sys.version_info.minor)')
PYMAJOR=$(echo "$PYVER" | cut -d' ' -f1)
PYMINOR=$(echo "$PYVER" | cut -d' ' -f2)
if [ "$PYMAJOR" -lt 3 ] || { [ "$PYMAJOR" -eq 3 ] && [ "$PYMINOR" -lt 11 ]; }; then
  echo "install: Python 3.11+ required, found $PYMAJOR.$PYMINOR" >&2
  exit 1
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -r requirements.txt

if [ ! -f PUBLIC-SHA256SUMS.txt ]; then
  echo "install: PUBLIC-SHA256SUMS.txt missing; do not trust this checkout" >&2
  exit 1
fi
sha256sum -c PUBLIC-SHA256SUMS.txt

echo "install: OK"
echo "Next: python3 experiments/OPENLINE-RELEASE-001/run_demo.py --dir /tmp/ol-demo"
echo "Then: see GETTING_STARTED.md for your first own project."
