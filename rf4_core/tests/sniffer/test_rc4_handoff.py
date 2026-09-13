"""rf4_core.sniffer：RC4 交接捕获与 bootstrap 恢复测试。"""
from __future__ import annotations

import unittest

from rf4_core.protocol import (
    RC4Stream,
    build_ack_frame,
    build_frame,
    build_request_envelope,
)
from rf4_core.sniffer import DiscoveryCandidate, PassiveSession

from rf4_core.tests.sniffer.helpers import TOKEN, _ctx, _make_observer


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

    def test_handoff_preserves_slot_items_mapping(self) -> None:
        # 回归：切服承接必须保留槽位→钓组映射，否则重启/切服后所有竿都
        # 反查不到竿号，搏鱼行全部回落"手持竿"。字段名必须与 FlowSession
        # 实际字段一致（slot_items），不能沿用参考版的 shortcut_items。
        _ctx()
        observer = _make_observer()
        session = PassiveSession.create("s3", observer.bridge)
        session.protocol.token = TOKEN
        session.protocol.auth_seen = True
        session.protocol.uuid_seen = True
        session.protocol.hermes_seen = True
        session.protocol.ensure_rc4()
        gear = "11111111-1111-1111-1111-111111111111"
        session.protocol.slot_items[1] = gear
        session.valid_business_frames = 3
        session.valid_client_frames = 1
        session.valid_server_frames = 1

        observer._remember_rc4_handoff(session)
        handoff = observer._rc4_handoffs.get(TOKEN)
        self.assertIsNotNone(handoff)
        assert handoff is not None
        self.assertEqual(handoff.fishing_state.get("slot_items"), {1: gear})

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
        result = observer._align_handoff_cipher(probe, data)
        self.assertIsNotNone(result)
        offset, encrypted_before = result
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
