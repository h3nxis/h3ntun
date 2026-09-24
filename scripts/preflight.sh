#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${1:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

[[ -n "${CONFIG_FILE}" && -f "${CONFIG_FILE}" ]] || {
  echo "usage: $0 /path/to/config.json" >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 1; }

PYTHONPATH="${PROJECT_DIR}" python3 -m asym_link check --config "${CONFIG_FILE}"
PYTHONPATH="${PROJECT_DIR}" python3 -m asym_link doctor --config "${CONFIG_FILE}"

if command -v timedatectl >/dev/null 2>&1; then
  timedatectl show --property=NTPSynchronized --property=TimeUSec --no-pager || true
fi
if command -v ip >/dev/null 2>&1; then
  REMOTE_IP="$(PYTHONPATH="${PROJECT_DIR}" python3 - "${CONFIG_FILE}" <<'PY'
import socket
import sys
from asym_link.config import IranConfig, load_config
config = load_config(sys.argv[1])
host = config.foreign_uplink[0] if isinstance(config, IranConfig) else config.iran_downlink[0]
print(socket.gethostbyname(host))
PY
)"
  ip -4 route get "${REMOTE_IP}"
fi

echo "preflight passed; no probe packet was sent"
