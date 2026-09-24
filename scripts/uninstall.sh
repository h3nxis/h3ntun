#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }
PURGE="${1:-}"

systemctl disable --now h3ntun.service 2>/dev/null || true
rm -f -- /etc/systemd/system/h3ntun.service
rm -rf -- /opt/h3ntun
systemctl daemon-reload

if [[ "${PURGE}" == "--purge" ]]; then
  rm -rf -- /etc/h3ntun /var/lib/h3ntun
  userdel h3ntun 2>/dev/null || true
  groupdel h3ntun 2>/dev/null || true
  echo "application, configuration, state and service account removed"
else
  echo "application removed; configuration and state were preserved"
fi
