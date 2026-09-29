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
        for path in self.db_path.parent.iterdir():
            path.chmod(0o666)  # 只读库会让 Windows 删不掉临时目录
        bridge.ctx = self._previous_ctx
        self._tmp.cleanup()

    def test_cleanup_only_runs_every_n_writes(self) -> None:
        ids_before = self._seed_old_events()

        self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')

        self.assertEqual(self._ids(), ids_before + [2001])
        self.assertEqual(self.bridge._overlay_writes_since_cleanup, 1)

    def test_cleanup_deletes_by_id_threshold(self) -> None:
        self._seed_old_events()
        self.bridge._overlay_writes_since_cleanup = self.bridge.OVERLAY_CLEANUP_EVERY_WRITES - 1

        self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')

        self.assertIsNotNone(self.bridge._overlay_con)
        self.assertEqual(self._ids(), [2, 2001])

    def test_write_failures_rebuild_corrupt_db(self) -> None:
        self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')
        self.bridge._close_overlay_db()
        self.db_path.chmod(0o444)  # 写不进去，等价于库损坏后的持续失败

        for _ in range(self.bridge.OVERLAY_CORRUPT_WRITE_FAILURES):
            self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')

        self.assertEqual(len(self._archived()), 1, "损坏库应改名隔离而不是原地覆盖")
        self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')
        self.assertEqual(self._ids(), [1], "重建后的库应能继续写入")

    def test_write_failure_below_threshold_keeps_file(self) -> None:
        self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')
        self.bridge._close_overlay_db()
        self.db_path.chmod(0o444)

        for _ in range(self.bridge.OVERLAY_CORRUPT_WRITE_FAILURES - 1):
            self.bridge._write_overlay_event("fish_incoming", '{"event":"fish_incoming"}')

        self.assertEqual(self._archived(), [])

    def _archived(self) -> list[Path]:
        return [p for p in self.db_path.parent.iterdir() if ".corrupt-" in p.name]

    def _seed_old_events(self) -> list[int]:
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
        return [1, 2]

    def _ids(self) -> list[int]:
        con = sqlite3.connect(self.db_path)
        try:
            return [row[0] for row in con.execute("SELECT id FROM overlay_events ORDER BY id")]
        finally:
            con.close()
