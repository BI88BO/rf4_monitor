"""rf4_core.bridge：浮窗 SQLite 长连接与清理测试。"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from rf4_core import bridge
from rf4_core.bridge import RF4ChatBridge


class OverlayDbTests(unittest.TestCase):
    def setUp(self) -> None:
        self._previous_ctx = bridge.ctx
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "overlay.sqlite3"
        self.bridge = RF4ChatBridge()
        bridge.ctx = SimpleNamespace(
            options=SimpleNamespace(
                rf4_overlay_db=str(self.db_path),
                rf4_verbose_logging=False,
            ),
            log=SimpleNamespace(info=lambda *_args, **_kwargs: None),
        )

    def tearDown(self) -> None:
        self.bridge._close_overlay_db()
        bridge.ctx = self._previous_ctx
        self._tmp.cleanup()

    def test_cleanup_deletes_by_id_threshold(self) -> None:
        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                "CREATE TABLE overlay_events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ts REAL NOT NULL,"
                "event_type TEXT NOT NULL,"
                "payload TEXT NOT NULL)"
            )
            con.executemany(
                "INSERT INTO overlay_events (id, ts, event_type, payload) VALUES (?, ?, ?, ?)",
                [(1, 0.0, "fish_incoming", "{}"), (2, 1.0, "fish_incoming", "{}")],
            )
            con.execute(
                "UPDATE sqlite_sequence SET seq = 2000 WHERE name = 'overlay_events'"
            )
            con.commit()
        finally:
            con.close()

        self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')

        self.assertIsNotNone(self.bridge._overlay_con)
        con = sqlite3.connect(self.db_path)
        try:
            ids = [row[0] for row in con.execute("SELECT id FROM overlay_events ORDER BY id")]
        finally:
            con.close()
        self.assertEqual(ids, [2, 2001])
