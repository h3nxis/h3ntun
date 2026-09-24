#!/usr/bin/env bash
set -euo pipefail

# Source NAT helper for addresses that are assigned to this server.
# It deliberately refuses non-local source addresses and never changes sysctl.

fail() {
  echo "error: $*" >&2
  exit 1
}

validate_ipv4() {
  local ip="$1" field="$2" octet
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "invalid IPv4 for ${field}: ${ip}"
  IFS='.' read -r -a octets <<< "${ip}"
  for octet in "${octets[@]}"; do
    (( 10#${octet} >= 0 && 10#${octet} <= 255 )) || fail "invalid IPv4 for ${field}: ${ip}"
  done
}

validate_port() {
  local port="$1" field="$2"
  [[ "${port}" =~ ^[0-9]+$ ]] || fail "invalid ${field}: ${port}"
  (( port >= 1 && port <= 65535 )) || fail "invalid ${field}: ${port}"
}

source_is_local() {
  ip -4 address show to "$1/32" | grep -qE '^[[:space:]]*inet[[:space:]]'
}

usage() {
  echo "Usage:"
  echo "  sudo $0 --apply  <destination_ip> <assigned_source_ip> [destination_port=7001] [source_port=7002]"
  echo "  sudo $0 --remove <destination_ip> <assigned_source_ip> [destination_port=7001] [source_port=7002]"
  echo "  sudo $0 --status"
}

ACTION="${1:---help}"
if [[ "${ACTION}" == "--help" || "${ACTION}" == "-h" ]]; then
  usage
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || fail "run as root"
command -v ip >/dev/null 2>&1 || fail "iproute2 is required"
command -v iptables >/dev/null 2>&1 || fail "iptables is required"

if [[ "${ACTION}" == "--status" ]]; then
  iptables -t nat -L POSTROUTING -n -v --line-numbers
  exit 0
fi

[[ "${ACTION}" == "--apply" || "${ACTION}" == "--remove" ]] || fail "select --apply or --remove"
shift
[[ $# -ge 2 ]] || { usage; exit 1; }

DESTINATION_IP="$1"
SOURCE_IP="$2"
DESTINATION_PORT="${3:-7001}"
SOURCE_PORT="${4:-7002}"
validate_ipv4 "${DESTINATION_IP}" "destination_ip"
validate_ipv4 "${SOURCE_IP}" "assigned_source_ip"
validate_port "${DESTINATION_PORT}" "destination_port"
validate_port "${SOURCE_PORT}" "source_port"

source_is_local "${SOURCE_IP}" || fail "source IP is not assigned to this server: ${SOURCE_IP}"

RULE=(
  -d "${DESTINATION_IP}" -p udp --dport "${DESTINATION_PORT}"
  -m comment --comment "h3ntun-source-nat"
  -j SNAT --to-source "${SOURCE_IP}:${SOURCE_PORT}"
)

if [[ "${ACTION}" == "--apply" ]]; then
  if iptables -t nat -C POSTROUTING "${RULE[@]}" 2>/dev/null; then
    echo "rule already present"
  else
    iptables -t nat -A POSTROUTING "${RULE[@]}"
    echo "source NAT rule added for an assigned local address"
  fi
else
  if iptables -t nat -C POSTROUTING "${RULE[@]}" 2>/dev/null; then
    iptables -t nat -D POSTROUTING "${RULE[@]}"
    echo "source NAT rule removed"
  else
    echo "rule not present"
  fi
fi
