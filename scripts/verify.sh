#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${1:-/etc/h3ntun/config.json}"
APP_DIR="/opt/h3ntun/app"
H3NTUN_BIN="/opt/h3ntun/venv/bin/h3ntun"
[[ -f "${CONFIG_FILE}" ]] || { echo "error: config not found: ${CONFIG_FILE}" >&2; exit 1; }
[[ -d "${APP_DIR}/h3ntun" ]] || { echo "error: application is not installed" >&2; exit 1; }
[[ -x "${H3NTUN_BIN}" ]] || { echo "error: h3ntun virtual environment is missing" >&2; exit 1; }

"${H3NTUN_BIN}" verify --config "${CONFIG_FILE}"
systemctl is-active --quiet h3ntun.service
echo "service and authenticated traffic checks passed"
