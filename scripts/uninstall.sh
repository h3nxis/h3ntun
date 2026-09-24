#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }
PURGE="${1:-}"

systemctl disable --now hy-asym-link.service 2>/dev/null || true
rm -f -- /etc/systemd/system/hy-asym-link.service
rm -rf -- /opt/hy-asym-link
systemctl daemon-reload

if [[ "${PURGE}" == "--purge" ]]; then
  rm -rf -- /etc/hy-asym-link /var/lib/hy-asym-link
  userdel hy-asym-link 2>/dev/null || true
  groupdel hy-asym-link 2>/dev/null || true
  echo "application, configuration, state and service account removed"
else
  echo "application removed; configuration and state were preserved"
fi
