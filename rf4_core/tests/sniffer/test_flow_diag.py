"""rf4_core.sniffer：切服诊断窗口测试。"""
from __future__ import annotations

import unittest
from unittest import mock

from rf4_core import sniffer
from rf4_core.sniffer import PassiveSession

from rf4_core.tests.sniffer.helpers import _auth_packet, _ctx, _make_observer


class FlowDiagTests(unittest.TestCase):
    """切服诊断窗口：统计判死后所有 TCP 流，定位被放行的业务连接。"""

    def _observer_with_closed_host(self) -> PacketObserver:
        observer = _make_observer()
        observer._closed_realtime_hosts.add("91.132.228.133")
        return observer

    def test_diag_records_flows_before_filtering(self) -> None:
        _ctx()
        observer = self._observer_with_closed_host()
        observer._start_flow_diag()
        # 业务流：纯加密续传，无 auth 特征、非 SYN —— 正常会被放行，但诊断要能看到。
        observer._handle_auto_packet(
            src="192.168.2.8", sport=40001, dst="185.71.66.225", dport=9347,
            seq=100, payload=b"\x13\x00\x00\x00\x02" + b"\xaa" * 30, flags=0x18,
        )
        observer._handle_auto_packet(
            src="185.71.66.225", sport=9347, dst="192.168.2.8", dport=40001,
            seq=200, payload=b"\x23\x00\x00\x00\x00" + b"\xbb" * 80, flags=0x18,
        )
        key = (("185.71.66.225", 9347), ("192.168.2.8", 40001))
        flow = observer._diag_flows.get(key)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.packets, 2)
        self.assertEqual(flow.bytes_by_ep.get(("192.168.2.8", 40001)), 35)
        self.assertEqual(flow.bytes_by_ep.get(("185.71.66.225", 9347)), 85)
        self.assertFalse(flow.saw_syn)

    def test_diag_auth_feature_detected(self) -> None:
        _ctx()
        observer = self._observer_with_closed_host()
        observer._start_flow_diag()
        # 带 auth 的流：诊断表应能识别 auth 特征。
        observer._handle_auto_packet(
            src="192.168.2.8", sport=40002, dst="185.71.66.225", dport=9347,
            seq=100, payload=_auth_packet(), flags=0x18,
        )
        key = (("185.71.66.225", 9347), ("192.168.2.8", 40002))
        flow = observer._diag_flows.get(key)
        self.assertIsNotNone(flow)
        assert flow is not None
        auth_seen = (
            sniffer.core.try_parse_auth_packet(bytes(flow.auth_buf_by_ep.get(("192.168.2.8", 40002), b"")))
            is not None
        )
        self.assertTrue(auth_seen)

    def test_diag_dumps_after_window_and_resets(self) -> None:
        _ctx()
        observer = self._observer_with_closed_host()
        observer._start_flow_diag()
        observer._handle_auto_packet(
            src="192.168.2.8", sport=40003, dst="185.71.66.225", dport=9347,
            seq=100, payload=b"\x01", flags=0x18,
        )
        self.assertIsNotNone(observer._diag_deadline)
        self.assertTrue(observer._diag_flows)
        # 窗口未到：不 dump。
        clock = {"t": sniffer.time.monotonic()}
        with mock.patch.object(sniffer.time, "monotonic", lambda: clock["t"]):
            observer._maybe_dump_flow_diag()
        self.assertTrue(observer._diag_flows)
        # 窗口到期：dump 并清空。
        clock["t"] += sniffer.FLOW_DIAG_WINDOW_SECONDS + 1.0
        with mock.patch.object(sniffer.time, "monotonic", lambda: clock["t"]):
            observer._maybe_dump_flow_diag()
        self.assertIsNone(observer._diag_deadline)
        self.assertFalse(observer._diag_flows)

    def test_fail_auto_session_starts_diag(self) -> None:
        _ctx()
        observer = _make_observer()
        session = PassiveSession.create("s-diag", observer.bridge)
        old_key = (("91.132.228.133", 9347), ("192.168.2.8", 41000))
        observer._auto_sessions[old_key] = (session, ("192.168.2.8", 41000))
        observer._fail_auto_session(old_key, session, ValueError("超时"))
        self.assertIsNotNone(observer._diag_deadline)
        self.assertIn(old_key, observer._retry_candidate_keys)
