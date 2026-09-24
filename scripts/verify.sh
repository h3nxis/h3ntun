#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${1:-/etc/hy-asym-link/config.json}"
APP_DIR="/opt/hy-asym-link/app"
[[ -f "${CONFIG_FILE}" ]] || { echo "error: config not found: ${CONFIG_FILE}" >&2; exit 1; }
[[ -d "${APP_DIR}/asym_link" ]] || { echo "error: application is not installed" >&2; exit 1; }

PYTHONPATH="${APP_DIR}" python3 -m asym_link verify --config "${CONFIG_FILE}"
systemctl is-active --quiet hy-asym-link.service
echo "service and authenticated traffic checks passed"
