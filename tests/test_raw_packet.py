import socket
import struct
import unittest

from asym_link.raw_udp import build_ipv4_udp_packet, internet_checksum


class PacketBuilderTests(unittest.TestCase):
    def test_ipv4_and_udp_checksums(self) -> None:
        source = "127.0.0.2"
        destination = "127.0.0.1"
        payload = b"offline-lab"
        packet = build_ipv4_udp_packet(source, 40000, destination, 40001, payload, packet_id=7)

        self.assertEqual(len(packet), 20 + 8 + len(payload))
        self.assertEqual(internet_checksum(packet[:20]), 0)

        udp = packet[20:]
        pseudo = (
            socket.inet_aton(source)
            + socket.inet_aton(destination)
            + struct.pack("!BBH", 0, socket.IPPROTO_UDP, len(udp))
        )
        self.assertEqual(internet_checksum(pseudo + udp), 0)


if __name__ == "__main__":
    unittest.main()
