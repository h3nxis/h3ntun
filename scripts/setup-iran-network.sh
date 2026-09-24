#!/usr/bin/env bash
set -euo pipefail

# Scoped route and reverse-path-filter helper with rollback state.
# It never disables rp_filter globally; loose mode (2) is applied per interface.

STATE_DIR="/var/lib/h3ntun/network-state"

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

validate_interface() {
  local interface="$1"
  [[ "${interface}" =~ ^[a-zA-Z0-9_.:-]+$ ]] || fail "invalid interface name"
  ip link show dev "${interface}" >/dev/null 2>&1 || fail "interface not found: ${interface}"
}

route_state_file() {
  local destination="$1"
  echo "${STATE_DIR}/route-${destination//./_}.state"
}

rp_state_file() {
  local interface="$1"
  echo "${STATE_DIR}/rp-filter-${interface}.state"
}

save_existing_route_once() {
  local destination="$1" state_file
  state_file="$(route_state_file "${destination}")"
  if [[ ! -e "${state_file}" ]]; then
    ip -4 route show exact "${destination}/32" > "${state_file}"
  fi
}

usage() {
  echo "Usage:"
  echo "  sudo $0 --set-rp-filter-loose <inbound_interface>"
  echo "  sudo $0 --restore-rp-filter <inbound_interface>"
  echo "  sudo $0 --route-dev <foreign_ip> <outbound_interface>"
  echo "  sudo $0 --route-gw <foreign_ip> <outbound_gateway> [outbound_interface]"
  echo "  sudo $0 --restore-route <foreign_ip>"
  echo "  sudo $0 --status [foreign_ip] [interface]"
}

[[ "${EUID}" -eq 0 ]] || fail "run as root"
command -v ip >/dev/null 2>&1 || fail "iproute2 is required"
command -v sysctl >/dev/null 2>&1 || fail "sysctl is required"
install -d -m 0700 "${STATE_DIR}"

ACTION="${1:---help}"
case "${ACTION}" in
  --help|-h)
    usage
    ;;

  --set-rp-filter-loose)
    [[ $# -eq 2 ]] || fail "provide exactly one inbound interface"
    INTERFACE="$2"
    validate_interface "${INTERFACE}"
    STATE_FILE="$(rp_state_file "${INTERFACE}")"
    if [[ ! -e "${STATE_FILE}" ]]; then
      sysctl -n "net.ipv4.conf.${INTERFACE}.rp_filter" > "${STATE_FILE}"
    fi
    sysctl -w "net.ipv4.conf.${INTERFACE}.rp_filter=2"
    echo "rp_filter loose mode applied only to ${INTERFACE}"
    ;;

  --restore-rp-filter)
    [[ $# -eq 2 ]] || fail "provide exactly one inbound interface"
    INTERFACE="$2"
    validate_interface "${INTERFACE}"
    STATE_FILE="$(rp_state_file "${INTERFACE}")"
    [[ -f "${STATE_FILE}" ]] || fail "no saved rp_filter state for ${INTERFACE}"
    PREVIOUS="$(<"${STATE_FILE}")"
    [[ "${PREVIOUS}" =~ ^[012]$ ]] || fail "saved rp_filter state is invalid"
    sysctl -w "net.ipv4.conf.${INTERFACE}.rp_filter=${PREVIOUS}"
    rm -f -- "${STATE_FILE}"
    echo "rp_filter restored on ${INTERFACE}"
    ;;

  --route-dev)
    [[ $# -eq 3 ]] || fail "provide foreign_ip and outbound_interface"
    DESTINATION="$2"
    INTERFACE="$3"
    validate_ipv4 "${DESTINATION}" "foreign_ip"
    validate_interface "${INTERFACE}"
    save_existing_route_once "${DESTINATION}"
    ip -4 route replace "${DESTINATION}/32" dev "${INTERFACE}"
    ip -4 route get "${DESTINATION}"
    ;;

  --route-gw)
    [[ $# -eq 3 || $# -eq 4 ]] || fail "provide foreign_ip, outbound_gateway and optional interface"
    DESTINATION="$2"
    GATEWAY="$3"
    validate_ipv4 "${DESTINATION}" "foreign_ip"
    validate_ipv4 "${GATEWAY}" "outbound_gateway"
    save_existing_route_once "${DESTINATION}"
    if [[ $# -eq 4 ]]; then
      INTERFACE="$4"
      validate_interface "${INTERFACE}"
      ip -4 route replace "${DESTINATION}/32" via "${GATEWAY}" dev "${INTERFACE}"
    else
      ip -4 route replace "${DESTINATION}/32" via "${GATEWAY}"
    fi
    ip -4 route get "${DESTINATION}"
    ;;

  --restore-route)
    [[ $# -eq 2 ]] || fail "provide foreign_ip"
    DESTINATION="$2"
    validate_ipv4 "${DESTINATION}" "foreign_ip"
    STATE_FILE="$(route_state_file "${DESTINATION}")"
    [[ -f "${STATE_FILE}" ]] || fail "no saved route state for ${DESTINATION}"
    if [[ -s "${STATE_FILE}" ]]; then
      read -r -a PREVIOUS_ROUTE < "${STATE_FILE}"
      ip -4 route replace "${PREVIOUS_ROUTE[@]}"
    else
      ip -4 route del "${DESTINATION}/32" 2>/dev/null || true
    fi
    rm -f -- "${STATE_FILE}"
    echo "route state restored for ${DESTINATION}"
    ;;

  --status)
    if [[ -n "${2:-}" ]]; then
      validate_ipv4 "$2" "foreign_ip"
      ip -4 route get "$2"
    fi
    if [[ -n "${3:-}" ]]; then
      validate_interface "$3"
      sysctl "net.ipv4.conf.${3}.rp_filter"
    fi
    echo "saved rollback state:"
    find "${STATE_DIR}" -maxdepth 1 -type f -print
    ;;

  *)
    usage
    fail "unknown action: ${ACTION}"
    ;;
esac
