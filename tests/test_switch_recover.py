from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core import sniffer
from rf4_core.bridge import RF4ChatBridge
from rf4_core.protocol import (
    RC4Stream,
    build_ack_frame,
    build_frame,
    build_request_envelope,
)
from rf4_core.sniffer import DiscoveryCandidate, PacketObserver, PassiveSession

TOKEN = "user|server|nonce|secret"


def _ctx():
    options = SimpleNamespace(
        rf4_log_plain_frames=False,
        rf4_verbose_logging=False,
        rf4_log_telemetry=True,
        rf4_telemetry_categories="all",
        rf4_event_bridge_port=0,
        rf4_default_location_id="",
        rf4_default_users_count=0,
    )
    sniffer.core.ctx = SimpleNamespace(options=options)
    sniffer._bridge_mod.ctx = sniffer.core.ctx
    return options


def _make_bridge():
    bridge = RF4ChatBridge()
    bridge._handle_client_frame = lambda _session, _plain: (b"", [])
    bridge._handle_server_frame = lambda _session, _plain: b""
    bridge._maybe_log_telemetry_frame = lambda *_args, **_kwargs: None
    return bridge


def _make_observer(bridge=None):
    if bridge is None:
        bridge = _make_bridge()
    return PacketObserver(realtime_port=0, bridge=bridge)


def _feed_auth_handshake(observer: PacketObserver) -> tuple[object, str]:
    """模拟一次完整的 auth 握手 + 业务帧，返回 (key, token)。"""
    client = ("192.168.2.8", 30000)
    server = ("91.132.228.133", 9453)
    key = (client[0], client[1], server[0], server[1])
    seq = 1000
    for payload in (_auth_packet(), b"\x01\x00\x00\x00\x00"):
        observer._handle_auto_packet(
            src=client[0], sport=client[1], dst=server[0], dport=server[1],
            seq=seq, payload=payload, flags=0x18,
        )
        seq += len(payload)
    # 触发 candidate 提升
    candidate = observer._candidates[key]
    server_data = bytes(candidate.buffers.get(server, b""))
    if server_data:
        client_endpoint = candidate.find_auth_endpoint()
        observer._promote_candidate(key, candidate, client_endpoint)
    session = observer._auto_sessions[key][0]
    return key, session


def _auth_packet() -> bytes:
    import struct
    token_b = TOKEN.encode()
    return b"\x01\x00" + struct.pack("<I", len(token_b)) + token_b


class Rc4HandoffCaptureTests(unittest.TestCase):
    def test_remember_and_take_roundtrip(self) -> None:
        _ctx()
        observer = _make_observer()
        bridge = observer.bridge
        session = PassiveSession.create("s1", bridge)
        session.protocol.token = TOKEN
        session.protocol.auth_seen = True
        session.protocol.uuid_seen = True
        session.protocol.hermes_seen = True
        session.protocol.ensure_rc4()
        session.protocol.server_read_rc4.crypt(b"some data")
        session.valid_business_frames = 3

        observer._remember_rc4_handoff(session)
        self.assertIn(TOKEN, observer._rc4_handoffs)
        handoff = observer._take_rc4_handoff(TOKEN)
        self.assertIsNotNone(handoff)
        self.assertEqual(handoff.token, TOKEN)

    def test_remember_rejects_without_business_frames(self) -> None:
        _ctx()
        observer = _make_observer()
        session = PassiveSession.create("s2", observer.bridge)
        session.protocol.token = TOKEN
        session.protocol.ensure_rc4()
        observer._remember_rc4_handoff(session)
        self.assertNotIn(TOKEN, observer._rc4_handoffs)

    def test_find_auth_endpoint_accepts_x0101_prefix(self) -> None:
        # 切服新连接若带 \x01\x01 开头的 auth 包（游戏钓鱼站重连场景），
        # find_auth_endpoint 必须能识别，否则会漏掉 auth 掉进 bootstrap 探测。
        _ctx()
        import struct

        token_b = TOKEN.encode()
        auth = b"\x01\x01" + struct.pack("<I", len(token_b)) + token_b
        candidate = DiscoveryCandidate(
            endpoints=("192.168.2.8", 30002, "185.71.66.225", 9443),
            created_at=0.0,
            updated_at=0.0,
            suspected_server=("185.71.66.225", 9443),
        )
        candidate.buffers[("192.168.2.8", 30002)] = bytearray(auth)
        self.assertEqual(candidate.find_auth_endpoint(), ("192.168.2.8", 30002))


class HandoffBootstrapTests(unittest.TestCase):
    def test_align_handoff_cipher_finds_frame_after_preamble(self) -> None:
        _ctx()
        observer = _make_observer()
        ref = RC4Stream(TOKEN.encode())
        plain = build_request_envelope(call_id=7, main_cmd=14, sub_cmd=4, payload=b"x")
        encrypted = build_frame(0, 101, ref.crypt(plain))
        data = build_ack_frame(1) + build_ack_frame(2) + encrypted

        probe = RC4Stream(TOKEN.encode())
        offset = observer._align_handoff_cipher(probe, data)
        self.assertIsNotNone(offset)
        self.assertEqual(offset, len(build_ack_frame(1)) + len(build_ack_frame(2)))
        self.assertEqual(data[offset:], encrypted)

    def test_align_handoff_cipher_returns_none_on_garbage(self) -> None:
        _ctx()
        observer = _make_observer()
        probe = RC4Stream(TOKEN.encode())
        self.assertIsNone(observer._align_handoff_cipher(probe, os_bytes := b"\x00" * 64))

    def test_bootstrap_recovers_switch_without_auth(self) -> None:
        _ctx()
        observer = _make_observer()
        bridge = observer.bridge
        # 旧服务器会话：完成握手并验证业务帧。
        old_client = ("192.168.2.8", 30000)
        old_server = ("91.132.228.133", 9453)
        old_key = (old_client[0], old_client[1], old_server[0], old_server[1])
        old_session = PassiveSession.create("old", bridge)
        old_session.protocol.token = TOKEN
        old_session.protocol.auth_seen = True
        old_session.protocol.uuid_seen = True
        old_session.protocol.hermes_seen = True
        old_session.protocol.ensure_rc4()
        ref = RC4Stream(TOKEN.encode())
        plain = build_request_envelope(call_id=1, main_cmd=14, sub_cmd=4, payload=b"old")
        old_session._process_server_bytes(build_frame(0, 100, ref.crypt(plain)))
        self.assertGreater(old_session.valid_business_frames, 0)
        observer._auto_sessions[old_key] = (old_session, old_client)
        observer._remove_auto_session(old_key, old_session)
        self.assertIn(TOKEN, observer._rc4_handoffs)

        # 切服到新服务器：同 token，无 auth，纯加密业务流（含 ACK 前置）。
        new_server = ("185.71.66.225", 9443)
        new_key = (old_client[0], old_client[1], new_server[0], new_server[1])
        new_ref = RC4Stream(TOKEN.encode())
        plain_new = build_request_envelope(call_id=2, main_cmd=14, sub_cmd=4, payload=b"new")
        encrypted = build_frame(0, 200, new_ref.crypt(plain_new))
        stream = build_ack_frame(10) + encrypted

        seq = 5000
        observer._handle_auto_packet(
            src=old_client[0], sport=old_client[1], dst=new_server[0], dport=new_server[1],
            seq=seq, payload=b"", flags=0x02,
        )
        seq += 1
        # 服务器下行：ACK 前置 + 加密业务帧（切服后无 auth）。
        observer._handle_auto_packet(
            src=new_server[0], sport=new_server[1], dst=old_client[0], dport=old_client[1],
            seq=seq, payload=stream, flags=0x18,
        )

        self.assertEqual(len(observer._auto_sessions), 1)
        session, _client = next(iter(observer._auto_sessions.values()))
        self.assertEqual(session.protocol.token, TOKEN)
        self.assertTrue(session.protocol.handshake_complete())
        self.assertGreater(session.valid_business_frames, 0)

    def test_bootstrap_requires_server_frame_validation(self) -> None:
        _ctx()
        observer = _make_observer()
        # 无任何 handoff 时不得建立会话。
        new_server = ("185.71.66.225", 9443)
        new_key = ("192.168.2.8", 30001, new_server[0], new_server[1])
        ref = RC4Stream(TOKEN.encode())
        plain = build_request_envelope(call_id=3, main_cmd=14, sub_cmd=4, payload=b"x")
        encrypted = build_frame(0, 300, ref.crypt(plain))
        observer._handle_auto_packet(
            src="192.168.2.8", sport=30001, dst=new_server[0], dport=new_server[1],
            seq=9000, payload=b"", flags=0x02,
        )
        observer._handle_auto_packet(
            src="192.168.2.8", sport=30001, dst=new_server[0], dport=new_server[1],
            seq=9001, payload=encrypted, flags=0x18,
        )
        self.assertNotIn(new_key, observer._auto_sessions)


class HermesGreetingTests(unittest.TestCase):
    def test_control_frame_before_hermes_is_skipped(self) -> None:
        # 切服重连时客户端可能在 <hermes> 问候帧前先发空控制帧
        # （body_len<=1，payload 为空）。旧逻辑遇到第一个非问候帧直接把会话
        # 判死，导致浮窗断粮；现在应跳过控制帧继续等待。
        _ctx()
        session = PassiveSession.create("s-hermes", _make_bridge())
        session._process_client_bytes(_auth_packet() + b"\x01\x00\x00\x00\x00")
        self.assertTrue(session.protocol.auth_seen)
        self.assertFalse(session.protocol.hermes_seen)
        # 问候帧随后到达：正常完成握手。
        session._process_client_bytes(build_frame(0, 0, b"<hermes>"))
        self.assertTrue(session.protocol.hermes_seen)

    def test_failed_session_is_torn_down_and_flow_reprobes(self) -> None:
        # 会话解析异常后必须现场拆除（failed 标志 + 移出注册表），并把该流
        # 标记为可重新探测；否则坏会话会每个包重复抛错、bootstrap 永远无法
        # 介入恢复。
        _ctx()
        observer = _make_observer()
        client = ("192.168.2.8", 31000)
        old_server = ("91.132.228.133", 9453)
        old_key = (client[0], client[1], old_server[0], old_server[1])
        session = PassiveSession.create("old-broken", observer.bridge)
        session.protocol.token = TOKEN
        session.protocol.auth_seen = True
        session.protocol.uuid_seen = True
        session.protocol.hermes_seen = True
        session.protocol.ensure_rc4()
        session.valid_business_frames = 2
        observer._auto_sessions[old_key] = (session, client)
        observer.sessions[(client[0], client[1], old_server[0], old_server[1])] = session
        observer._remember_rc4_handoff(session)
        self.assertIn(TOKEN, observer._rc4_handoffs)

        observer._fail_auto_session(old_key, session, ValueError("认证包后未找到 Hermes 明文握手"))

        self.assertTrue(session.failed)
        self.assertNotIn(old_key, observer._auto_sessions)
        self.assertNotIn((client[0], client[1], old_server[0], old_server[1]), observer.sessions)
        self.assertIn(old_key, observer._retry_candidate_keys)

    def test_retry_flag_lets_midstream_flow_bootstrap(self) -> None:
        # 复现线上事故路径：切服连接解析失败被拆除后，同一四元组继续来包
        # （无 SYN、首字节是密文不是 auth），必须仍能建 candidate 走
        # handoff bootstrap 中途恢复。
        _ctx()
        observer = _make_observer()
        ref = RC4Stream(TOKEN.encode())
        plain = build_request_envelope(call_id=9, main_cmd=14, sub_cmd=4, payload=b"resume")
        encrypted = build_frame(0, 900, ref.crypt(plain))
        stream = build_ack_frame(11) + encrypted

        broken_key = ("192.168.2.8", 32000, "185.71.66.225", 9443)
        observer._rc4_handoffs[TOKEN] = sniffer.Rc4Handoff(
            token=TOKEN,
            client_read_rc4=RC4Stream(TOKEN.encode()),
            server_read_rc4=RC4Stream(TOKEN.encode()),
            saved_at=sniffer.time.monotonic(),
        )
        # FlowKey 与 _handle_auto_packet 一致按字典序排序：
        # ("185.71.66.225", 9443) 排在 ("192.168.2.8", 32000) 之前。
        observer._retry_candidate_keys.add(
            (("185.71.66.225", 9443), ("192.168.2.8", 32000))
        )

        seq = 7000
        # 客户端上行包先建立 candidate（事故场景：同一四元组持续来包，无 SYN）。
        observer._handle_auto_packet(
            src="192.168.2.8", sport=32000, dst="185.71.66.225", dport=9443,
            seq=seq, payload=b"", flags=0x18,
        )
        seq += 1
        observer._handle_auto_packet(
            src="185.71.66.225", sport=9443, dst="192.168.2.8", dport=32000,
            seq=seq, payload=stream, flags=0x18,
        )

        self.assertEqual(len(observer._auto_sessions), 1)
        _key, (session, client) = next(iter(observer._auto_sessions.items()))
        # 方向必须正确：客户端是 192.168.2.8，服务器是 185.71.66.225
        # （旧逻辑按字典序取 key[0] 会把 185.x 当客户端、方向颠倒）。
        self.assertEqual(client, ("192.168.2.8", 32000))
        self.assertEqual(
            session.session_id, "192.168.2.8:32000 -> 185.71.66.225:9443"
        )
        self.assertEqual(session.protocol.token, TOKEN)
        self.assertTrue(session.protocol.handshake_complete())
        self.assertGreater(session.valid_business_frames, 0)


if __name__ == "__main__":
    unittest.main()