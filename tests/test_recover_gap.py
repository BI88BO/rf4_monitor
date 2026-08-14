from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core import sniffer
from rf4_core.bridge import RF4ChatBridge
from rf4_core.protocol import RC4Stream, build_frame, build_request_envelope
from rf4_core.sniffer import PassiveSession, TcpStreamReassembler


class TcpStreamReassemblerGapRecoveryTests(unittest.TestCase):
    def test_recovers_small_gap_by_skipping_to_pending_segment(self) -> None:
        stream = TcpStreamReassembler(next_seq=10)
        self.assertEqual(stream.feed(15, b"world"), b"")
        gap_bytes, chunk = stream.recover_gap(max_gap_bytes=8)
        self.assertEqual(gap_bytes, 5)
        self.assertEqual(chunk, b"world")
        self.assertEqual(stream.next_seq, 20)
        self.assertEqual(stream.pending_bytes, 0)

    def test_chains_contiguous_fragments_after_recovery(self) -> None:
        stream = TcpStreamReassembler(next_seq=10)
        self.assertEqual(stream.feed(15, b"world"), b"")
        self.assertEqual(stream.feed(20, b"!!"), b"")
        gap_bytes, chunk = stream.recover_gap(max_gap_bytes=8)
        self.assertEqual(gap_bytes, 5)
        self.assertEqual(chunk, b"world!!")
        self.assertEqual(stream.next_seq, 22)

    def test_leaves_uncontiguous_fragments_pending_after_recovery(self) -> None:
        stream = TcpStreamReassembler(next_seq=10)
        self.assertEqual(stream.feed(15, b"world"), b"")
        self.assertEqual(stream.feed(23, b"!!"), b"")
        gap_bytes, chunk = stream.recover_gap(max_gap_bytes=8)
        self.assertEqual(gap_bytes, 5)
        self.assertEqual(chunk, b"world")
        self.assertEqual(stream.next_seq, 20)
        self.assertEqual(stream.first_pending_seq(), 23)

    def test_refuses_large_gap_recovery(self) -> None:
        stream = TcpStreamReassembler(next_seq=10)
        self.assertEqual(stream.feed(50, b"later"), b"")
        gap_bytes, chunk = stream.recover_gap(max_gap_bytes=8)
        self.assertEqual(gap_bytes, 0)
        self.assertEqual(chunk, b"")
        self.assertEqual(stream.first_pending_seq(), 50)

    def test_returns_zero_when_no_fragments_pending(self) -> None:
        stream = TcpStreamReassembler(next_seq=10)
        gap_bytes, chunk = stream.recover_gap(max_gap_bytes=8)
        self.assertEqual(gap_bytes, 0)
        self.assertEqual(chunk, b"")

    def test_bounded_gap_size_constant_larger_than_zero(self) -> None:
        self.assertGreater(sniffer.MAX_RECOVERABLE_TCP_GAP_BYTES, 0)


def _make_ready_session() -> PassiveSession:
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
    bridge = RF4ChatBridge()
    bridge._handle_client_frame = lambda _session, _plain: (b"", [])
    bridge._handle_server_frame = lambda _session, _plain: b""
    bridge._maybe_log_telemetry_frame = lambda *_args, **_kwargs: None
    session = PassiveSession.create("test", bridge)
    session.protocol.token = "user|server|nonce|secret"
    session.protocol.auth_seen = True
    session.protocol.uuid_seen = True
    session.protocol.hermes_seen = True
    session.protocol.ensure_rc4()
    return session


class PassiveSessionGapRecoveryTests(unittest.TestCase):
    def test_refuses_recovery_when_no_verifiable_frame(self) -> None:
        # 缺口后只有裸字节（无帧结构），信封校验无法确认同步点 → 拒绝恢复。
        session = _make_ready_session()
        session.server_tcp.next_seq = 100
        session.feed_tcp(from_client=False, seq=106, payload=b"world", syn=False)
        session.protocol.server_buffer.extend(b"half-frame")

        gap_bytes, chunk = session._recover_tcp_gap(
            session.server_tcp, from_client=False, direction="服务器下行"
        )
        self.assertEqual(gap_bytes, 0)
        self.assertEqual(chunk, b"")
        # 拒绝恢复时不清空既有 buffer，也不推进 RC4。
        self.assertEqual(session.protocol.server_buffer, bytearray(b"half-frame"))
        reference = RC4Stream(session.protocol.token.encode())
        marker = b"hello"
        self.assertEqual(
            session.protocol.server_read_rc4.crypt(marker),
            reference.crypt(marker),
        )

    def test_feed_tcp_refuses_recovery_without_verifiable_frame(self) -> None:
        session = _make_ready_session()
        session.server_tcp.next_seq = 100
        session.feed_tcp(from_client=False, seq=106, payload=b"world", syn=False)
        self.assertEqual(session.server_tcp.next_seq, 100)

        session.server_tcp.gap_started_at = 0.0
        session.feed_tcp(from_client=False, seq=0, payload=b"", syn=False)

        # 无有效帧可校验 → 恢复被拒绝，next_seq 停留在缺口起点。
        self.assertEqual(session.server_tcp.next_seq, 100)
        self.assertGreater(session.server_tcp.pending_bytes, 0)

    def test_handshake_complete_required_before_recovery(self) -> None:
        session = _make_ready_session()
        session.protocol.auth_seen = False
        session.server_tcp.next_seq = 100
        session.feed_tcp(from_client=False, seq=106, payload=b"world", syn=False)
        session.server_tcp.gap_started_at = 0.0
        gap_bytes, _chunk = session._recover_tcp_gap(
            session.server_tcp, from_client=False, direction="服务器下行"
        )
        self.assertEqual(gap_bytes, 0)
        self.assertEqual(session.server_tcp.next_seq, 100)


class PassiveSessionEnvelopeResyncTests(unittest.TestCase):
    """缺口内混有明文帧头时，恢复必须只跳过缺口内的密文字节，
    并通过信封校验重新同步 RC4，否则后续帧解密全部错位。"""

    def _build_stream(self) -> tuple[PassiveSession, list[bytes]]:
        """Return (session, received_plains) where ref mirrors server RC4,
        and frame 2 (a whole frame incl. its 13-byte header) is dropped in the middle.
        The bridge handler records every decrypted server frame plaintext."""
        session = _make_ready_session()
        received: list[bytes] = []
        session.bridge._handle_server_frame = lambda _session, plain: received.append(plain)
        # 独立参考流模拟服务器端加密（与 session.server_read_rc4 同 key 同起点）。
        ref = RC4Stream(session.protocol.token.encode())
        # 帧1：正常传输（先到，无缺口）。
        plain1 = build_request_envelope(call_id=1, main_cmd=14, sub_cmd=4, payload=b"x")
        raw1 = build_frame(0, 101, ref.crypt(plain1))
        # 帧2：完整一帧在缺口内丢失（13 字节帧头 + payload 全丢）。
        plain2 = build_request_envelope(call_id=2, main_cmd=14, sub_cmd=4, payload=b"y")
        raw2 = build_frame(0, 102, ref.crypt(plain2))
        # 帧3：缺口后到达的帧，必须能正确解密。
        plain3 = build_request_envelope(call_id=3, main_cmd=14, sub_cmd=4, payload=b"z")
        raw3 = build_frame(0, 103, ref.crypt(plain3))

        seq = 1000
        session.feed_tcp(from_client=False, seq=seq, payload=raw1, syn=False)
        seq += len(raw1)
        # 帧2 从未到达（模拟丢包）：seq 直接跳到 raw2 之后。
        seq += len(raw2)
        # 帧3 到达。
        session.feed_tcp(from_client=False, seq=seq, payload=raw3, syn=False)
        return session, [plain1, plain3]

    def test_resync_skips_only_ciphertext_not_headers(self) -> None:
        session, _received = self._build_stream()
        pending_seq = session.server_tcp.first_pending_seq()
        gap_bytes = pending_seq - session.server_tcp.next_seq
        self.assertEqual(gap_bytes, 25)
        pending_data = session.server_tcp.fragments[pending_seq]
        result = PassiveSession._resync_gap_cipher(
            session.protocol.server_read_rc4, pending_data, gap_bytes
        )
        self.assertIsNotNone(result)
        lost, fpos = result
        # 缺口 25 字节里只有 12 字节是密文 payload（帧头 13 字节不进 RC4）。
        self.assertEqual(lost, 12)
        self.assertEqual(fpos, 0)

    def test_recovers_when_gap_inside_frame_header_and_payload(self) -> None:
        """缺口吃掉了帧头(13字节)+部分payload，帧2的残留密文会混在缺口后数据里。
        恢复必须正确找到帧3边界并跳过残留，不产生错位解析。"""
        session = _make_ready_session()
        received: list[object] = []
        session.bridge._handle_server_frame = lambda _session, plain: received.append(
            __import__("rf4_core.protocol", fromlist=["parse_envelope"]).parse_envelope(plain)
        )
        ref = RC4Stream(session.protocol.token.encode())
        plain1 = build_request_envelope(call_id=1, main_cmd=14, sub_cmd=4, payload=b"x")
        raw1 = build_frame(0, 101, ref.crypt(plain1))
        plain2 = build_request_envelope(call_id=2, main_cmd=14, sub_cmd=4, payload=bytes([0x59]) * 10)
        raw2 = build_frame(0, 102, ref.crypt(plain2))
        plain3 = build_request_envelope(call_id=3, main_cmd=14, sub_cmd=4, payload=b"z")
        raw3 = build_frame(0, 103, ref.crypt(plain3))

        seq = 1000
        session.feed_tcp(from_client=False, seq=seq, payload=raw1, syn=False)
        seq += len(raw1)
        # 缺口 = 帧2的 13 字节帧头 + 5 字节 payload；缺口后 = 帧2剩余密文 + 帧3。
        gap_inside = 18
        seq += gap_inside
        remaining = raw2[gap_inside:] + raw3
        session.feed_tcp(from_client=False, seq=seq, payload=remaining, syn=False)
        session.server_tcp.gap_started_at = 0.0
        session.feed_tcp(from_client=False, seq=0, payload=b"", syn=False)

        # 帧1 与帧3 正确到达，帧2 被跳过，不 stall。
        ids = [env.call_id for env in received if env is not None]
        self.assertEqual(ids, [1, 3])
        self.assertFalse(session.downlink_stalled)

    def test_recovers_when_gap_contains_full_frame_with_header(self) -> None:
        session, received = self._build_stream()
        session.server_tcp.gap_started_at = 0.0
        session.feed_tcp(from_client=False, seq=0, payload=b"", syn=False)

        # 恢复后 next_seq 跳过整个缺口。
        self.assertEqual(session.server_tcp.pending_bytes, 0)
        self.assertEqual(session.server_tcp.next_seq, 1000 + 25 + 25 + 25)
        # 缺口后的帧3 被正确解密送达 handler。
        self.assertEqual(len(received), 2)
        self.assertEqual(received[1], build_request_envelope(call_id=3, main_cmd=14, sub_cmd=4, payload=b"z"))

    def test_waits_for_tcp_retransmission_before_recovery(self) -> None:
        """游戏端会等数据包重新到位：缺口出现后若 TCP 重传在恢复阈值内补齐，
        帧2 必须无缝续上且不被跳过，缺口内帧内容不丢。"""
        session, _received = self._build_stream()
        # 缺口存在但 age 未到恢复阈值（模拟刚发生乱序，等重传补齐）。
        self.assertGreater(session.server_tcp.pending_bytes, 0)
        self.assertLess(session.server_tcp.gap_age(), sniffer.TCP_GAP_RECOVERY_SECONDS)

        # 帧2 的密文以乱序包到达（TCP 重传/乱序），落在缺口位置。
        ref = RC4Stream(session.protocol.token.encode())
        plain1 = build_request_envelope(call_id=1, main_cmd=14, sub_cmd=4, payload=b"x")
        ref.crypt(plain1)
        plain2 = build_request_envelope(call_id=2, main_cmd=14, sub_cmd=4, payload=b"y")
        raw2 = build_frame(0, 102, ref.crypt(plain2))

        from rf4_core.sniffer import PassiveSession

        called = {"recovery": False}
        original = PassiveSession._recover_tcp_gap

        def patched(self, *args, **kwargs):
            called["recovery"] = True
            return original(self, *args, **kwargs)

        PassiveSession._recover_tcp_gap = patched
        try:
            # 缺口起点 = 帧2 的位置，帧2 乱序到达补齐缺口。
            gap_start = session.server_tcp.next_seq
            session.feed_tcp(from_client=False, seq=gap_start, payload=raw2, syn=False)
        finally:
            PassiveSession._recover_tcp_gap = original

        # 缺口被补齐，未触发跳过恢复。
        self.assertFalse(called["recovery"])
        self.assertEqual(session.server_tcp.pending_bytes, 0)
        self.assertEqual(
            session.server_tcp.next_seq,
            1000 + 25 + 25 + 25,
        )