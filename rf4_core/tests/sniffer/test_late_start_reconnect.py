"""监控晚启动（游戏先开）强制重连接管测试。"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from rf4_core import sniffer as capture
from rf4_core.protocol import build_frame
from rf4_core.sniffer import CapturedTcpPacket, PacketObserver

from rf4_core.tests.sniffer.helpers import _ctx, _make_bridge, _make_observer


def _bidirectional_packets(client, server, payload, count=2):
    packets = [
        CapturedTcpPacket(client[0], client[1], server[0], server[1], 100 + i, payload, 0x10)
        for i in range(count)
    ]
    packets.extend(
        CapturedTcpPacket(server[0], server[1], client[0], client[1], 200 + i, payload, 0x10)
        for i in range(count)
    )
    return packets


class LateStartReconnectTests(unittest.TestCase):
    def test_bidirectional_encrypted_flow_resets_once(self) -> None:
        _ctx()
        observer = _make_observer()
        payload = build_frame(0, 77, b"x" * 32)
        client = ("192.168.1.20", 61000)
        server = ("91.132.228.133", 56499)
        reset_calls = []

        def fake_reset(left, right):
            reset_calls.append((left, right))
            return True, "reset-ok"

        packets = _bidirectional_packets(client, server, payload)
        with (
            patch.object(capture, "LATE_START_RECONNECT_OBSERVE_SECONDS", 0.0),
            patch.object(capture, "LATE_START_RECONNECT_MIN_PACKETS", 4),
            patch.object(capture, "LATE_START_RECONNECT_MIN_BYTES", 1),
            patch.object(capture, "_reset_windows_ipv4_tcp_connection", fake_reset),
        ):
            for packet in packets:
                observer.handle_packet(packet)
            observer.handle_packet(packets[-1])

        self.assertEqual(reset_calls, [observer._flow_key(client, server)])

    def test_no_reset_when_below_packet_threshold(self) -> None:
        _ctx()
        observer = _make_observer()
        payload = build_frame(0, 78, b"x" * 32)
        client = ("192.168.1.21", 61001)
        server = ("91.132.228.134", 56500)
        reset_calls = []

        with (
            patch.object(capture, "LATE_START_RECONNECT_OBSERVE_SECONDS", 0.0),
            patch.object(capture, "LATE_START_RECONNECT_MIN_PACKETS", 4),
            patch.object(capture, "LATE_START_RECONNECT_MIN_BYTES", 1),
            patch.object(
                capture,
                "_reset_windows_ipv4_tcp_connection",
                lambda left, right: (reset_calls.append((left, right)), (True, "ok"))[1],
            ),
        ):
            for packet in _bidirectional_packets(client, server, payload, count=1):
                observer.handle_packet(packet)

        self.assertEqual(reset_calls, [])

    def test_disabled_flag_skips_reset(self) -> None:
        _ctx()
        observer = PacketObserver(
            realtime_port=0, bridge=_make_bridge(), late_start_reconnect=False
        )
        payload = build_frame(0, 79, b"x" * 32)
        client = ("192.168.1.22", 61002)
        server = ("91.132.228.135", 56501)
        reset_calls = []

        with (
            patch.object(capture, "LATE_START_RECONNECT_OBSERVE_SECONDS", 0.0),
            patch.object(capture, "LATE_START_RECONNECT_MIN_PACKETS", 1),
            patch.object(capture, "LATE_START_RECONNECT_MIN_BYTES", 1),
            patch.object(
                capture,
                "_reset_windows_ipv4_tcp_connection",
                lambda left, right: (reset_calls.append((left, right)), (True, "ok"))[1],
            ),
        ):
            for packet in _bidirectional_packets(client, server, payload):
                observer.handle_packet(packet)

        self.assertEqual(reset_calls, [])


if __name__ == "__main__":
    unittest.main()
