from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core import sniffer
from rf4_core.bridge import RF4ChatBridge
from rf4_core.protocol import RC4Stream, build_frame
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
    def test_recover_tcp_gap_advances_rc4_and_clears_buffer(self) -> None:
        session = _make_ready_session()
        session.server_tcp.next_seq = 100
        session.feed_tcp(from_client=False, seq=106, payload=b"world", syn=False)
        session.protocol.server_buffer.extend(b"half-frame")

        gap_bytes, chunk = session._recover_tcp_gap(
            session.server_tcp, from_client=False, direction="服务器下行"
        )
        self.assertEqual(gap_bytes, 6)
        self.assertEqual(chunk, b"world")
        self.assertEqual(session.protocol.server_buffer, bytearray())

        reference = RC4Stream(session.protocol.token.encode())
        reference.keystream(6)
        marker = b"hello"
        self.assertEqual(
            session.protocol.server_read_rc4.crypt(marker),
            reference.crypt(marker),
        )

    def test_feed_tcp_recovers_gap_after_timeout(self) -> None:
        session = _make_ready_session()
        session.server_tcp.next_seq = 100
        session.feed_tcp(from_client=False, seq=106, payload=b"world", syn=False)
        self.assertEqual(session.server_tcp.next_seq, 100)

        session.server_tcp.gap_started_at = 0.0
        session.feed_tcp(from_client=False, seq=0, payload=b"", syn=False)

        self.assertEqual(session.server_tcp.next_seq, 111)
        self.assertEqual(session.server_tcp.pending_bytes, 0)

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