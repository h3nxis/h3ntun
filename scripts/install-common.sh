#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-}"
CONFIG_SOURCE="${2:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="/opt/hy-asym-link/app"
INSTALL_SCRIPTS_DIR="/opt/hy-asym-link/scripts"
CONFIG_DIR="/etc/hy-asym-link"
STATE_DIR="/var/lib/hy-asym-link"
SERVICE_FILE="/etc/systemd/system/hy-asym-link.service"

fail() {
  echo "error: $*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "run this installer as root"
[[ "${ROLE}" == "iran" || "${ROLE}" == "foreign" ]] || fail "role must be iran or foreign"
[[ -n "${CONFIG_SOURCE}" ]] || fail "usage: $0 ${ROLE} /path/to/config.json"
[[ -f "${CONFIG_SOURCE}" ]] || fail "configuration file not found: ${CONFIG_SOURCE}"
[[ -f "${PROJECT_DIR}/pyproject.toml" ]] || fail "run from the extracted project bundle"
[[ -f "${PROJECT_DIR}/systemd/hy-asym-link.service" ]] || fail "systemd unit is missing"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("error: Python 3.10 or newer is required")
PY

CONFIG_ROLE="$(PYTHONPATH="${PROJECT_DIR}" python3 - "${CONFIG_SOURCE}" <<'PY'
import sys
from asym_link.config import load_config
print(load_config(sys.argv[1]).role)
PY
)"
[[ "${CONFIG_ROLE}" == "${ROLE}" ]] || fail "config role is ${CONFIG_ROLE}, expected ${ROLE}"

if ! getent group hy-asym-link >/dev/null 2>&1; then
  groupadd --system hy-asym-link
fi
if ! id hy-asym-link >/dev/null 2>&1; then
  useradd --system --gid hy-asym-link --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin hy-asym-link
fi

install -d -m 0755 "${APP_DIR}/asym_link" "${INSTALL_SCRIPTS_DIR}" "${CONFIG_DIR}"
install -d -o hy-asym-link -g hy-asym-link -m 0750 "${STATE_DIR}"
find "${PROJECT_DIR}/asym_link" -maxdepth 1 -type f -name '*.py' -exec install -m 0644 {} "${APP_DIR}/asym_link/" \;
find "${PROJECT_DIR}/scripts" -maxdepth 1 -type f -name '*.sh' -exec install -m 0755 {} "${INSTALL_SCRIPTS_DIR}/" \;
find "${PROJECT_DIR}/scripts" -maxdepth 1 -type f -name '*.py' -exec install -m 0755 {} "${INSTALL_SCRIPTS_DIR}/" \;
find "${PROJECT_DIR}/scripts" -maxdepth 1 -type f -name '*.txt' -exec install -m 0644 {} "${INSTALL_SCRIPTS_DIR}/" \;
install -m 0644 "${PROJECT_DIR}/pyproject.toml" "${APP_DIR}/pyproject.toml"
install -o root -g hy-asym-link -m 0640 "${CONFIG_SOURCE}" "${CONFIG_DIR}/config.json"
install -m 0644 "${PROJECT_DIR}/systemd/hy-asym-link.service" "${SERVICE_FILE}"

PYTHONPATH="${APP_DIR}" python3 -m asym_link check --config "${CONFIG_DIR}/config.json"
systemctl daemon-reload
systemctl enable --now hy-asym-link.service
systemctl --no-pager --full status hy-asym-link.service || true

echo "installed role=${ROLE}"
echo "verify with: sudo bash ${INSTALL_SCRIPTS_DIR}/verify.sh"
