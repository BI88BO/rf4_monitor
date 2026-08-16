from __future__ import annotations

import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core.sniffer import _parse_raw_eth_tcp_packet


def _eth_frame(
    *,
    src: str = "192.168.2.8",
    dst: str = "91.132.228.133",
    sport: int = 4126,
    dport: int = 9190,
    seq: int = 123456,
    payload: bytes = b"hello",
    flags: int = 0x18,
    ipv6: bool = False,
    checksum_garbage: bool = False,
) -> bytes:
    if not ipv6:
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + 20 + len(payload),
            0x0000,
            0x4000,
            64,
            6,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            seq,
            0,
            0x50,
            flags,
            65535,
            0,
            0,
        )
        eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
        return eth + ip_header + tcp_header + payload
    else:
        # IPv6: 40-byte header, next header = TCP (6)
        ip6_header = (
            b"\x60\x00\x00\x00"
            + struct.pack("!H", 20 + len(payload))
            + b"\x06\x40"
            + socket.inet_pton(socket.AF_INET6, "fe80::1")
            + socket.inet_pton(socket.AF_INET6, "fe80::2")
        )
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            seq,
            0,
            0x50,
            flags,
            65535,
            0,
            0,
        )
        eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x86\xdd"
        return eth + ip6_header + tcp_header + payload


class ParseRawEthTcpPacketTests(unittest.TestCase):
    def test_parses_ipv4_tcp_payload(self) -> None:
        packet = _parse_raw_eth_tcp_packet(_eth_frame(payload=b"business"))
        self.assertIsNotNone(packet)
        self.assertEqual(packet.src, "192.168.2.8")
        self.assertEqual(packet.dst, "91.132.228.133")
        self.assertEqual(packet.sport, 4126)
        self.assertEqual(packet.dport, 9190)
        self.assertEqual(packet.seq, 123456)
        self.assertEqual(packet.payload, b"business")
        self.assertEqual(packet.flags, 0x18)

    def test_parses_ipv6_tcp_payload(self) -> None:
        packet = _parse_raw_eth_tcp_packet(_eth_frame(payload=b"v6data", ipv6=True))
        self.assertIsNotNone(packet)
        self.assertEqual(packet.payload, b"v6data")
        self.assertEqual(packet.sport, 4126)
        self.assertEqual(packet.dport, 9190)

    def test_returns_none_for_non_ip_ethertype(self) -> None:
        frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x06" + b"\x00" * 40
        self.assertIsNone(_parse_raw_eth_tcp_packet(frame))

    def test_returns_none_for_short_frame(self) -> None:
        self.assertIsNone(_parse_raw_eth_tcp_packet(b"\x00" * 14))

    def test_returns_none_for_short_tcp(self) -> None:
        # IP header claims 20+8 bytes but only 20 IP + 4 TCP bytes present
        eth = b"\x00" * 12 + b"\x08\x00"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8, 0, 0x4000, 64, 6, 0, b"\x00" * 4, b"\x00" * 4)
        frame = eth + ip + b"\x00" * 4
        self.assertIsNone(_parse_raw_eth_tcp_packet(frame))

    def test_preserves_syn_flag(self) -> None:
        packet = _parse_raw_eth_tcp_packet(_eth_frame(flags=0x02, payload=b""))
        self.assertIsNotNone(packet)
        self.assertEqual(packet.flags & 0x02, 0x02)
        self.assertEqual(packet.payload, b"")


if __name__ == "__main__":
    unittest.main()