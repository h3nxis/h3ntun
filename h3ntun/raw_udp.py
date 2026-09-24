from __future__ import annotations

import ipaddress
import random
import socket
import struct


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_udp_packet(
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    payload: bytes,
    packet_id: int | None = None,
) -> bytes:
    src = ipaddress.IPv4Address(source_ip).packed
    dst = ipaddress.IPv4Address(destination_ip).packed
    if not 0 <= source_port <= 65535 or not 0 <= destination_port <= 65535:
        raise ValueError("UDP port is outside 0..65535")
    if len(payload) > 65_507:
        raise ValueError("UDP payload is too large")
    udp_len = 8 + len(payload)
    udp_header_zero = struct.pack("!HHHH", source_port, destination_port, udp_len, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
    udp_checksum = internet_checksum(pseudo + udp_header_zero + payload) or 0xFFFF
    udp_header = struct.pack("!HHHH", source_port, destination_port, udp_len, udp_checksum)

    total_len = 20 + udp_len
    packet_id = random.randint(0, 65535) if packet_id is None else packet_id
    ip_header_zero = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        packet_id,
        0x4000,
        64,
        socket.IPPROTO_UDP,
        0,
        src,
        dst,
    )
    ip_checksum = internet_checksum(ip_header_zero)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        packet_id,
        0x4000,
        64,
        socket.IPPROTO_UDP,
        ip_checksum,
        src,
        dst,
    )
    return ip_header + udp_header + payload


class NormalUDPSender:
    def __init__(self, bind: tuple[str, int] = ("0.0.0.0", 0)):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(bind)

    def sendto(self, payload: bytes, destination: tuple[str, int]) -> None:
        self.socket.sendto(payload, destination)

    def close(self) -> None:
        self.socket.close()
