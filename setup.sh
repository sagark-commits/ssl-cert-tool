#!/usr/bin/env bash
# Author: Sagar K | 2026 | MIT licence
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
exec python3 setup.py
