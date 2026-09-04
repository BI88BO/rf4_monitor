"""sniffer 测试共享工具。"""
from __future__ import annotations

import struct
from types import SimpleNamespace

from rf4_core import sniffer
from rf4_core.bridge import RF4ChatBridge
from rf4_core.sniffer import PacketObserver, PassiveSession

TOKEN = "user|server|nonce|secret"


def _ctx():
    options = SimpleNamespace(
        rf4_log_plain_frames=False,
        rf4_verbose_logging=False,
        rf4_log_telemetry=True,
        rf4_telemetry_categories="all",
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


def _auth_packet() -> bytes:
    token_b = TOKEN.encode()
    return b"\x01\x00" + struct.pack("<I", len(token_b)) + token_b


def _make_ready_session() -> PassiveSession:
    _ctx()
    session = PassiveSession.create("test", _make_bridge())
    session.protocol.token = TOKEN
    session.protocol.auth_seen = True
    session.protocol.uuid_seen = True
    session.protocol.hermes_seen = True
    session.protocol.ensure_rc4()
    return session
