"""rf4_core.sniffer：会话结束通知浮窗清空（小退清屏、镜像流退役不误清）。"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from rf4_core.sniffer import PassiveSession

from rf4_core.tests.sniffer.helpers import TOKEN, _ctx, _make_observer


class SessionEndNotifyTests(unittest.TestCase):
    def setUp(self) -> None:
        _ctx()
        self.observer = _make_observer()
        self.client = ("192.168.2.8", 30000)
        self.server = ("91.132.228.133", 9453)
        self.key = (self.client[0], self.client[1], self.server[0], self.server[1])
        self.session = PassiveSession.create("s-end", self.observer.bridge)
        self.session.protocol.token = TOKEN
        self.session.protocol.auth_seen = True
        self.session.protocol.uuid_seen = True
        self.session.protocol.hermes_seen = True
        self.session.protocol.ensure_rc4()
        self.session.valid_business_frames = 3
        self.session.valid_client_frames = 1
        self.session.valid_server_frames = 1

    def test_tcp_close_notifies_session_end(self) -> None:
        # 小退/断连：FIN 必须通知浮窗清空，否则旧竿行一直挂到下次抛竿。
        self.observer._auto_sessions[self.key] = (self.session, self.client)
        with mock.patch.object(
            self.observer.bridge, "broadcast_session_end"
        ) as notify:
            self.observer._remove_auto_session(self.key, self.session, flags=0x11, from_client=True)
        notify.assert_called_once_with()

    def test_mirrored_session_retirement_does_not_notify(self) -> None:
        # 加速器双抓的镜像流静默 2 秒就退役，真会话还在跑：
        # 这里若通知清空，浮窗会在钓鱼途中被整窗抹掉。
        mirror_key = ("192.168.9.9", 40000, self.server[0], self.server[1])
        self.observer._auto_sessions[mirror_key] = (self.session, ("192.168.9.9", 40000))
        self.session.last_packet_at = time.monotonic() - 30
        with mock.patch.object(
            self.observer.bridge, "broadcast_session_end"
        ) as notify:
            self.observer._retire_stale_mirrored_token_sessions(
                token=TOKEN,
                client_endpoint=self.client,
                exclude_key=self.key,
            )
        notify.assert_not_called()
        self.assertNotIn(mirror_key, self.observer._auto_sessions)

    def test_handoff_saved_even_when_notification_fails(self) -> None:
        self.observer._auto_sessions[self.key] = (self.session, self.client)
        with mock.patch.object(
            self.observer.bridge, "broadcast_session_end", side_effect=RuntimeError("db gone")
        ):
            self.observer._remove_auto_session(self.key, self.session)
        self.assertIn(TOKEN, self.observer._rc4_handoffs)
