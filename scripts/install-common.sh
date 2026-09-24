#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-}"
CONFIG_SOURCE="${2:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="/opt/h3ntun/app"
INSTALL_SCRIPTS_DIR="/opt/h3ntun/scripts"
CONFIG_DIR="/etc/h3ntun"
STATE_DIR="/var/lib/h3ntun"
VENV_DIR="/opt/h3ntun/venv"
SERVICE_FILE="/etc/systemd/system/h3ntun.service"

fail() {
  echo "error: $*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "run this installer as root"
[[ "${ROLE}" == "iran" || "${ROLE}" == "foreign" ]] || fail "role must be iran or foreign"
[[ -n "${CONFIG_SOURCE}" ]] || fail "usage: $0 ${ROLE} /path/to/config.json"
[[ -f "${CONFIG_SOURCE}" ]] || fail "configuration file not found: ${CONFIG_SOURCE}"
[[ -f "${PROJECT_DIR}/pyproject.toml" ]] || fail "run from the extracted project bundle"
[[ -f "${PROJECT_DIR}/systemd/h3ntun.service" ]] || fail "systemd unit is missing"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("error: Python 3.10 or newer is required")
PY

if ! getent group h3ntun >/dev/null 2>&1; then
  groupadd --system h3ntun
fi
if ! id h3ntun >/dev/null 2>&1; then
  useradd --system --gid h3ntun --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin h3ntun
fi

install -d -m 0755 "${APP_DIR}/h3ntun" "${INSTALL_SCRIPTS_DIR}" "${CONFIG_DIR}"
install -d -o h3ntun -g h3ntun -m 0750 "${STATE_DIR}"
find "${PROJECT_DIR}/h3ntun" -maxdepth 1 -type f -name '*.py' -exec install -m 0644 {} "${APP_DIR}/h3ntun/" \;
find "${PROJECT_DIR}/scripts" -maxdepth 1 -type f -name '*.sh' -exec install -m 0755 {} "${INSTALL_SCRIPTS_DIR}/" \;
find "${PROJECT_DIR}/scripts" -maxdepth 1 -type f -name '*.py' -exec install -m 0755 {} "${INSTALL_SCRIPTS_DIR}/" \;
find "${PROJECT_DIR}/scripts" -maxdepth 1 -type f -name '*.txt' -exec install -m 0644 {} "${INSTALL_SCRIPTS_DIR}/" \;
install -m 0644 "${PROJECT_DIR}/pyproject.toml" "${APP_DIR}/pyproject.toml"
install -o root -g h3ntun -m 0640 "${CONFIG_SOURCE}" "${CONFIG_DIR}/config.json"
install -m 0644 "${PROJECT_DIR}/systemd/h3ntun.service" "${SERVICE_FILE}"

python3 -m venv "${VENV_DIR}" || fail "python venv support is required"
"${VENV_DIR}/bin/python" -m pip install --disable-pip-version-check --no-cache-dir "${PROJECT_DIR}"

CONFIG_ROLE="$("${VENV_DIR}/bin/python" - "${CONFIG_DIR}/config.json" <<'PY'
import sys
from h3ntun.config import load_config
print(load_config(sys.argv[1]).role)
PY
)"
[[ "${CONFIG_ROLE}" == "${ROLE}" ]] || fail "config role is ${CONFIG_ROLE}, expected ${ROLE}"
"${VENV_DIR}/bin/h3ntun" check --config "${CONFIG_DIR}/config.json"

systemctl daemon-reload
systemctl enable --now h3ntun.service
systemctl --no-pager --full status h3ntun.service || true

echo "installed role=${ROLE}"
echo "verify with: sudo bash ${INSTALL_SCRIPTS_DIR}/verify.sh"
