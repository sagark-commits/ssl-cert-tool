#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Default deploy config: ../ssl-deploy/config.yaml (auto-discovered by ssl-pipeline.py if --config omitted)
DEFAULT_CONFIG="${SCRIPT_DIR}/../ssl-deploy/config.yaml"
PY=""
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
fi
if [[ -z "$PY" ]]; then
  echo "Python 3 is required to run ssl-pipeline.py." >&2
  echo "Install Python 3 and run: python ssl-pipeline.py ..." >&2
  exit 1
fi

# Auto-install dependencies if missing
if ! "$PY" -c "import cryptography" 2>/dev/null; then
  echo "Installing dependencies..."
  "$PY" -m pip install -r "$SCRIPT_DIR/requirements.txt"
fi

# When running "all" without --config, pass the default (forward slashes for WSL/Linux).
if [[ "${1:-}" == "all" ]]; then
  has_config=false
  for arg in "$@"; do
    if [[ "$arg" == "--config" || "$arg" == --config=* ]]; then
      has_config=true
      break
    fi
  done
  if [[ "$has_config" == false && -f "$DEFAULT_CONFIG" ]]; then
    set -- "$@" --config "$DEFAULT_CONFIG"
  fi
fi

exec "$PY" "$SCRIPT_DIR/ssl-pipeline.py" "$@"