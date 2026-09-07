"""deskmon_overlay：事件路由与 SQLite 轮询测试。"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

_OVERLAY_PATH = Path(__file__).resolve().parents[2] / "overlay.pyw"
_spec = importlib.util.spec_from_file_location("rf4_core.overlay", _OVERLAY_PATH)
overlay_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(overlay_mod)
Overlay = overlay_mod.Overlay


def _empty_overlay() -> Overlay:
    """Build an Overlay instance without touching Tk, wired to record calls."""
    calls: list[tuple] = []
    ov = object.__new__(Overlay)

    def record_self(gear_slot: str = "", text: str = "", clear_after: int = 0) -> None:
        calls.append(("self", gear_slot, text, clear_after))

    def record_generic(text: str) -> None:
        calls.append(("generic", text))

    def record_anticheat(text: str) -> None:
        calls.append(("anticheat", text))

    def record_reset() -> None:
        calls.append(("reset",))

    def record_show(gear_slot: str = "", text: str = "") -> None:
        calls.append(("self", gear_slot, text, 0))

    ov._show_self_event = record_self
    ov._show_generic = record_generic
    ov._show_anticheat = record_anticheat
    ov._reset_to_idle = record_reset
    ov.calls = calls
    return ov


class OverlayDatagramRoutingTests(unittest.TestCase):
    def test_self_events_route_to_show_self_event(self) -> None:
        ov = _empty_overlay()
        payload = json.dumps(
            {
                "event": "fish_incoming",
                "gear_slot": "2",
                "text": "【我自己】：有鱼过来了",
            },
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        # 事件短句化 + 来鱼保持到下一条事件覆盖(不再 8 秒自动消失)。
        self.assertEqual(ov.calls, [("self", "2", "鱼 来鱼", 0)])

    def test_kept_events_clear_after_three_seconds(self) -> None:
        ov = _empty_overlay()
        payload = json.dumps(
            {"event": "fish_kept", "gear_slot": "1", "text": "入护了"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(ov.calls, [("self", "1", "入护了", 3000)])

    def test_chat_and_telemetry_route_to_generic(self) -> None:
        ov = _empty_overlay()
        ov._handle_event_payload('{"event": "chat", "text": "hello"}')
        ov._handle_event_payload('{"event": "telemetry", "text": "w1"}')
        self.assertEqual(ov.calls, [("generic", "hello"), ("generic", "w1")])

    def test_reset_routes_to_reset_to_idle(self) -> None:
        ov = _empty_overlay()
        ov._handle_event_payload('{"event": "reset", "text": ""}')
        self.assertEqual(ov.calls, [("reset",)])

    def test_anticheat_routes_to_show_anticheat(self) -> None:
        ov = _empty_overlay()
        ov._handle_event_payload('{"event": "anticheat", "text": "ac"}')
        self.assertEqual(ov.calls, [("anticheat", "ac")])

    def test_real_show_anticheat_reroutes_without_label(self) -> None:
        # 真实 _show_anticheat 不再引用 self.label，改为 canvas 红字 8 秒后恢复。
        calls: list[tuple] = []
        after_calls: list[tuple] = []
        ov = object.__new__(Overlay)
        ov._anticheat_red = False
        ov._telemetry_rows = {}
        ov._telemetry_seq = 0
        ov._refresh_display = lambda: calls.append(("refresh",))
        ov._show_telemetry = lambda text: calls.append(("telemetry", text))
        ov.root = SimpleNamespace(after=lambda delay, fn: after_calls.append((delay, fn)))
        ov._show_anticheat("ac")
        self.assertFalse(hasattr(ov, "label"))
        self.assertTrue(ov._anticheat_red)
        self.assertEqual([c for c in calls if c[0] == "telemetry"], [("telemetry", "ac")])
        self.assertEqual([delay for delay, _ in after_calls], [8000])
        after_calls[0][1]()
        self.assertFalse(ov._anticheat_red)
        self.assertEqual(calls[-1], ("refresh",))

    def test_garbage_datagram_is_ignored(self) -> None:
        ov = _empty_overlay()
        ov._handle_event_payload("not-json")
        ov._handle_event_payload("")
        self.assertEqual(ov.calls, [])


class OverlayFightStatusTests(unittest.TestCase):
    def _overlay(self) -> Overlay:
        ov = object.__new__(Overlay)
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._telemetry_seq = 0
        ov._update_row = Overlay._update_row.__get__(ov)
        ov._refresh_display = lambda: None
        return ov

    def test_rod_prefixed_telemetry_updates_row_in_place(self) -> None:
        ov = self._overlay()
        payload = json.dumps(
            {"event": "telemetry", "category": "fish", "text": "3号杆 | 体力 78% 出线 12.3米"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(ov._rows.get("3号杆"), "3号杆 78% 12.3米")

    def test_fight_status_category_updates_rod_row(self) -> None:
        # 三档拆分后搏鱼状态行走 fight_status 类别，仍按号杆前缀就地更新。
        ov = self._overlay()
        payload = json.dumps(
            {"event": "telemetry", "category": "fight_status", "text": "1号杆 | 体力 100% 出线 33.486米"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(ov._rows.get("1号杆"), "1号杆 100% 33.486米")

    def test_handheld_fight_status_gets_own_row(self) -> None:
        # 手持竿搏鱼状态独立成行就地更新，不进遥测区闪现。
        ov = self._overlay()
        payload = json.dumps(
            {"event": "telemetry", "category": "fish",
             "text": "手持竿 | 鱼=蓝鳃太阳鱼 重量=1.553 公斤 体力 90% 出线 5.0米"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(ov._rows.get("手持竿"), "手持竿 蓝鳃太阳鱼1.553kg 90% 5.0米")

    def test_fight_details_goes_to_generic(self) -> None:
        # fight_details 无号杆前缀，进遥测区通用显示。
        ov = self._overlay()
        ov._show_generic = lambda text: ov._rows.__setitem__("generic", text)
        payload = json.dumps(
            {"event": "telemetry", "category": "fight_details", "text": "钓鱼过程位置上报 | 钓组=abc123"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(ov._rows.get("generic"), "钓鱼过程位置上报 | 钓组=abc123")

    def test_plain_telemetry_goes_to_generic(self) -> None:
        ov = self._overlay()
        ov._show_generic = lambda text: ov._rows.__setitem__("generic", text)
        ov._handle_event_payload('{"event":"telemetry","category":"player","text":"x=1"}')
        self.assertEqual(ov._rows.get("generic"), "x=1")
        self.assertNotIn("3号杆", ov._rows)

    def test_rod_sort_order(self) -> None:
        ov = object.__new__(Overlay)
        ov._rows = {"3号杆": "c", "1号杆": "a", "2号杆": "b"}
        keys = sorted(ov._rows, key=Overlay._rod_sort_key)
        self.assertEqual(keys, ["1号杆", "2号杆", "3号杆"])


class OverlayStartupHistoryTests(unittest.TestCase):
    def _poll_overlay(self) -> tuple[Overlay, list[tuple]]:
        import sqlite3

        calls: list[tuple] = []
        ov = object.__new__(Overlay)

        def record_self(gear_slot: str = "", text: str = "", clear_after: int = 0) -> None:
            calls.append(("self", gear_slot, text, clear_after))

        ov._show_self_event = record_self
        ov._show_generic = lambda text: calls.append(("generic", text))
        ov._reset_to_idle = lambda: calls.append(("reset",))
        ov._show_anticheat = lambda text: calls.append(("anticheat", text))
        ov.root = SimpleNamespace(after=lambda delay, fn: None)
        with tempfile.TemporaryDirectory() as tmp:
            ov.db_path = Path(tmp) / "overlay.sqlite3"
            ov._ensure_sqlite_db()
            con = sqlite3.connect(ov.db_path)
            try:
                con.execute(
                    "INSERT INTO overlay_events (ts, event_type, payload) VALUES (?, ?, ?)",
                    (1.0, "fish_incoming", '{"event": "fish_incoming", "text": "旧鱼"}'),
                )
                con.commit()
            finally:
                con.close()
            ov._last_seen_id = ov._latest_event_id()
            ov._poll()
            self.assertEqual(calls, [])
            con = sqlite3.connect(ov.db_path)
            try:
                con.execute(
                    "INSERT INTO overlay_events (ts, event_type, payload) VALUES (?, ?, ?)",
                    (2.0, "fish_incoming", '{"event": "fish_incoming", "text": "新鱼"}'),
                )
                con.commit()
            finally:
                con.close()
            ov._poll()
            ov._close_sqlite()
        return ov, calls

    def test_startup_skips_history_and_consumes_new_events(self) -> None:
        ov, calls = self._poll_overlay()
        self.assertEqual(calls, [("self", "", "新鱼", 0)])
        self.assertGreater(ov._last_seen_id, 1)

    def test_startup_cursor_uses_latest_database_id(self) -> None:
        import sqlite3

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "overlay.sqlite3"
            con = sqlite3.connect(path)
            try:
                con.execute(
                    "CREATE TABLE overlay_events ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "ts REAL NOT NULL,"
                    "event_type TEXT NOT NULL,"
                    "payload TEXT NOT NULL)"
                )
                con.execute(
                    "INSERT INTO overlay_events (ts, event_type, payload) VALUES (?, ?, ?)",
                    (1.0, "fish_incoming", "{}"),
                )
                con.commit()
            finally:
                con.close()
            ov = object.__new__(Overlay)
            ov.db_path = path
            try:
                self.assertEqual(ov._latest_event_id(), 1)
            finally:
                ov._close_sqlite()


class OverlaySqliteCursorTests(unittest.TestCase):
    def _overlay(self, db_path) -> Overlay:
        ov = object.__new__(Overlay)
        ov.db_path = db_path
        ov._last_seen_id = 0
        ov.root = SimpleNamespace(after=lambda delay, fn: None)
        calls: list[tuple] = []
        ov._handle_event_payload = lambda payload: calls.append(payload)
        ov._ensure_sqlite_db()
        ov.calls = calls
        return ov

    def _insert(self, db_path, ts: float, event: str, payload: str) -> None:
        import sqlite3

        con = sqlite3.connect(str(db_path))
        con.execute(
            "INSERT INTO overlay_events (ts, event_type, payload) VALUES (?, ?, ?)",
            (ts, event, payload),
        )
        con.commit()
        con.close()

    def test_poll_reads_events_after_bridge_restart_by_id_cursor(self) -> None:
        """回归：bridge 重启后 ts 归零，游标必须用自增 id 而非 ts。"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "events.sqlite3"
            ov = self._overlay(db)
            # bridge 第一次运行：ts 较大
            self._insert(db, 199009.0, "fish_incoming",
                         '{"event":"fish_incoming","gear_slot":"1","text":"old"}')
            ov._poll()
            self.assertEqual(len(ov.calls), 1)
            # bridge 重启：ts 从小的值重新开始，但 id 继续递增
            self._insert(db, 3.0, "fish_incoming",
                         '{"event":"fish_incoming","gear_slot":"1","text":"new"}')
            ov._poll()
            ov._close_sqlite()
            self.assertEqual(len(ov.calls), 2)
            self.assertIn("new", ov.calls[-1])

    def test_poll_does_not_replay_already_seen_events(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "events.sqlite3"
            ov = self._overlay(db)
            self._insert(db, 100.0, "reset", '{"event":"reset","text":""}')
            ov._poll()
            ov._close_sqlite()
            self.assertEqual(len(ov.calls), 1)
            try:
                ov._poll()
            finally:
                ov._close_sqlite()
            self.assertEqual(len(ov.calls), 1, "已读事件不应重复触发")
