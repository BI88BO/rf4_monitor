from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_OVERLAY_PATH = Path(__file__).resolve().parents[1] / "rf4_overlay.pyw"
_spec = importlib.util.spec_from_file_location("rf4_overlay", _OVERLAY_PATH)
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
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov.calls, [("self", "2", "【我自己】：有鱼过来了", 0)])

    def test_kept_events_clear_after_three_seconds(self) -> None:
        ov = _empty_overlay()
        payload = json.dumps(
            {"event": "fish_kept", "gear_slot": "1", "text": "入护了"},
            ensure_ascii=False,
        )
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov.calls, [("self", "1", "入护了", 3000)])

    def test_chat_and_telemetry_route_to_generic(self) -> None:
        ov = _empty_overlay()
        ov._handle_datagram(b'{"event": "chat", "text": "hello"}')
        ov._handle_datagram(b'{"event": "telemetry", "text": "w1"}')
        self.assertEqual(ov.calls, [("generic", "hello"), ("generic", "w1")])

    def test_reset_routes_to_reset_to_idle(self) -> None:
        ov = _empty_overlay()
        ov._handle_datagram(b'{"event": "reset", "text": ""}')
        self.assertEqual(ov.calls, [("reset",)])

    def test_anticheat_routes_to_show_anticheat(self) -> None:
        ov = _empty_overlay()
        ov._handle_datagram(b'{"event": "anticheat", "text": "ac"}')
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
        ov._handle_datagram(b"not-json")
        ov._handle_datagram(b"")
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
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov._rows.get("3号杆"), "3号杆 | 体力 78% 出线 12.3米")

    def test_fight_status_category_updates_rod_row(self) -> None:
        # 三档拆分后搏鱼状态行走 fight_status 类别，仍按号杆前缀就地更新。
        ov = self._overlay()
        payload = json.dumps(
            {"event": "telemetry", "category": "fight_status", "text": "1号杆 | 体力 100% 出线 33.486米"},
            ensure_ascii=False,
        )
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov._rows.get("1号杆"), "1号杆 | 体力 100% 出线 33.486米")

    def test_fight_details_goes_to_generic(self) -> None:
        # fight_details 无号杆前缀，进遥测区通用显示。
        ov = self._overlay()
        ov._show_generic = lambda text: ov._rows.__setitem__("generic", text)
        payload = json.dumps(
            {"event": "telemetry", "category": "fight_details", "text": "钓鱼过程位置上报 | 钓组=abc123"},
            ensure_ascii=False,
        )
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov._rows.get("generic"), "钓鱼过程位置上报 | 钓组=abc123")

    def test_plain_telemetry_goes_to_generic(self) -> None:
        ov = self._overlay()
        ov._show_generic = lambda text: ov._rows.__setitem__("generic", text)
        ov._handle_datagram(b'{"event":"telemetry","category":"player","text":"x=1"}')
        self.assertEqual(ov._rows.get("generic"), "x=1")
        self.assertNotIn("3号杆", ov._rows)

    def test_rod_sort_order(self) -> None:
        ov = object.__new__(Overlay)
        ov._rows = {"3号杆": "c", "1号杆": "a", "2号杆": "b"}
        keys = sorted(ov._rows, key=Overlay._rod_sort_key)
        self.assertEqual(keys, ["1号杆", "2号杆", "3号杆"])


class OverlayFightColorTests(unittest.TestCase):
    def test_exhausted_fight_row_is_red(self) -> None:
        ov = object.__new__(Overlay)
        row = "1号杆 | 体力 0% 出线 2.1米"
        self.assertEqual(Overlay._fight_row_color(row, "#ffd166"), "#ff5252")

    def test_active_fight_row_uses_default_color(self) -> None:
        ov = object.__new__(Overlay)
        row = "1号杆 | 体力 78% 出线 12.3米"
        self.assertEqual(Overlay._fight_row_color(row, "#ffd166"), "#ffd166")


class OverlayGlassStyleTests(unittest.TestCase):
    def test_glass_style_constants_defined(self) -> None:
        self.assertEqual(Overlay.CANVAS_BG, "#0F1916")
        self.assertEqual(Overlay.CANVAS_ACCENT, "#2EE6A8")
        self.assertEqual(Overlay.CANVAS_TEXT, "#4FF2C8")
        self.assertEqual(Overlay.CORNER_RADIUS, 12)

    def test_font_family_falls_back_when_missing(self) -> None:
        import tkinter.font as tkfont
        real = tkfont.families

        def fake_families(root=None):
            return ["Microsoft YaHei UI"]

        tkfont.families = fake_families
        Overlay._reset_font_family_cache()
        try:
            self.assertEqual(Overlay.font_family(), "Microsoft YaHei UI")
        finally:
            tkfont.families = real
            Overlay._reset_font_family_cache()

    def test_font_family_prefers_installed_chinese_font(self) -> None:
        import tkinter.font as tkfont
        real = tkfont.families

        def fake_families(root=None):
            return ["Arial", "三极芯片体 超粗"]

        tkfont.families = fake_families
        Overlay._reset_font_family_cache()
        try:
            self.assertEqual(Overlay.font_family(), "三极芯片体 超粗")
        finally:
            tkfont.families = real
            Overlay._reset_font_family_cache()


class OverlayGlassDrawTests(unittest.TestCase):
    def test_round_rect_draws_polygon_with_rounded_arcs(self) -> None:
        ov = object.__new__(Overlay)
        calls: list[tuple] = []
        canvas = type("C", (), {"create_polygon": lambda self, *a, **k: (calls.append(("polygon", a, k)) or 7)})()
        item = Overlay._round_rect(canvas, 0, 0, 100, 50, 12, fill="#000", outline="#111")
        self.assertEqual(item, 7)
        self.assertEqual(calls[0][0], "polygon")
        self.assertIn("smooth", calls[0][2])

    def test_ensure_canvas_builds_canvas_with_transparent_key_bg(self) -> None:
        # 真实 _ensure_canvas：canvas 背景必须用透明键 #0000FF，且只创建一次并缓存复用。
        ov = object.__new__(Overlay)
        ov.canvas = None
        ov.root = SimpleNamespace()
        created: dict = {}
        canvas = type("C", (), {
            "pack": lambda self, **kw: (created.update(pack=kw) or None),
            "delete": lambda self, tag: None,
            "create_text": lambda *a, **k: 1,
            "create_polygon": lambda *a, **k: 2,
            "create_line": lambda *a, **k: 3,
        })()
        real_canvas = overlay_mod.tk.Canvas

        def fake_canvas(root, **kw):
            created["count"] = created.get("count", 0) + 1
            created["opts"] = kw
            return canvas

        overlay_mod.tk.Canvas = fake_canvas
        try:
            got = ov._ensure_canvas()
            again = ov._ensure_canvas()
        finally:
            overlay_mod.tk.Canvas = real_canvas
        self.assertIs(got, canvas)
        self.assertIs(again, canvas)
        self.assertEqual(created["count"], 1)
        self.assertEqual(created["opts"]["bg"], Overlay.TRANSPARENT_KEY)
        self.assertEqual(created["opts"]["highlightthickness"], 0)


class OverlayGlassDrawFullTests(unittest.TestCase):
    def _overlay(self):
        ov = object.__new__(Overlay)
        ov.style = "dark"
        ov._rows = {"1号杆": "1号杆 | 体力 78% 出线 12.3米"}
        ov._telemetry_rows = {}
        created: list[tuple] = []
        canvas = type("C", (), {
            "delete": lambda self, tag: None,
            "create_polygon": lambda self, *a, **k: (created.append(("polygon", k)) or 1),
            "create_line": lambda self, *a, **k: (created.append(("line", k)) or 2),
            "create_text": lambda self, *a, **k: (created.append(("text", k)) or 3),
        })()
        ov.canvas = canvas
        ov._ensure_canvas = lambda: canvas
        ov._content_height = lambda lines: 60
        ov._show = lambda: None
        ov.created = created
        ov.root = SimpleNamespace()
        return ov

    def test_draw_renders_background_edge_accent_and_text(self) -> None:
        ov = self._overlay()
        ov._draw(width=320, height=60)
        kinds = [c[0] for c in ov.created]
        self.assertIn("polygon", kinds)  # 背景 + 描边
        self.assertIn("line", kinds)     # 装饰线
        self.assertIn("text", kinds)     # 文本
        bg = [k for k in ov.created if k[0] == "polygon"]
        self.assertTrue(all(k[1].get("fill") == "#0F1916" for k in bg))

    def test_exhausted_row_uses_red_text(self) -> None:
        ov = self._overlay()
        ov._rows = {"1号杆": "1号杆 | 体力 0% 出线 2.1米"}
        ov._draw(width=320, height=60)
        texts = [k for k in ov.created if k[0] == "text"]
        self.assertEqual(texts[0][1]["fill"], "#FF5252")

    def test_telemetry_rows_use_dim_color_and_follow_rod_block(self) -> None:
        ov = self._overlay()
        ov._rows = {"1号杆": "1号杆 | 体力 78% 出线 12.3米"}
        ov._telemetry_rows = {1: "商店折扣", 2: "装备已修复"}
        ov._draw(width=320, height=60)
        texts = [k for k in ov.created if k[0] == "text"]
        self.assertEqual(len(texts), 2)
        self.assertEqual(texts[0][1]["fill"], Overlay.CANVAS_TEXT)
        self.assertEqual(texts[0][1]["text"], "1号杆 | 体力 78% 出线 12.3米")
        self.assertEqual(texts[1][1]["fill"], Overlay.CANVAS_DIM)
        self.assertEqual(texts[1][1]["text"], "商店折扣\n装备已修复")
        # 第二块 y = 14 + 竿行数 × 行高(测试环境无 Tk，行高回退 28)
        self.assertEqual(texts[1][1]["y"], 14 + 1 * 28)

    def test_idle_fallback_line_is_dim(self) -> None:
        ov = self._overlay()
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._draw(width=320, height=60)
        texts = [k for k in ov.created if k[0] == "text"]
        self.assertEqual(len(texts), 1)
        self.assertEqual(texts[0][1]["fill"], Overlay.CANVAS_DIM)
        self.assertEqual(texts[0][1]["text"], "RF4 来鱼提醒 · 待机中")

    def test_transparent_mode_skips_glass_and_draws_text_only(self) -> None:
        ov = self._overlay()
        ov.style = Overlay.STYLE_TRANSPARENT
        ov._rows = {"1号杆": "1号杆 | 体力 78% 出线 12.3米"}
        ov._draw(width=320, height=60)
        kinds = [c[0] for c in ov.created]
        self.assertNotIn("polygon", kinds)
        self.assertNotIn("line", kinds)
        self.assertEqual([c[0] for c in ov.created if c[0] == "text"], ["text"])

    def test_anticheat_red_wins_over_normal_row_color(self) -> None:
        ov = self._overlay()
        ov._anticheat_red = True
        ov._rows = {"1号杆": "1号杆 | 体力 100% 出线 12.3米"}
        ov._draw(width=320, height=60)
        texts = [k for k in ov.created if k[0] == "text"]
        self.assertEqual(texts[0][1]["fill"], Overlay.CANVAS_RED)


class OverlayAnticheatTimerTests(unittest.TestCase):
    def test_second_anticheat_cancels_previous_clear_timer(self) -> None:
        ov = object.__new__(Overlay)
        after_calls: list[tuple] = []
        cancelled: list[int] = []
        ov.root = SimpleNamespace(
            after=lambda delay, fn: (after_calls.append((delay, fn)) or 7),
            after_cancel=lambda timer_id: cancelled.append(timer_id),
        )
        ov._anticheat_red = False
        ov._anticheat_timer_id = None
        ov._telemetry_rows = {}
        ov._telemetry_seq = 0
        ov._refresh_display = lambda: None
        ov._show_telemetry = lambda text: None
        ov._show_anticheat("first")
        ov._show_anticheat("second")
        self.assertEqual(len(after_calls), 2)
        self.assertEqual(cancelled, [7])

    def test_clear_anticheat_resets_timer_id(self) -> None:
        ov = object.__new__(Overlay)
        after_calls: list[tuple] = []
        ov.root = SimpleNamespace(
            after=lambda delay, fn: (after_calls.append((delay, fn)) or 7),
            after_cancel=lambda timer_id: None,
        )
        ov._anticheat_red = True
        ov._anticheat_timer_id = 7
        ov._telemetry_rows = {}
        ov._telemetry_seq = 0
        ov._refresh_display = lambda: None
        ov._show_telemetry = lambda text: None
        ov._show_anticheat("ac")
        self.assertEqual(ov._anticheat_timer_id, 7)
        after_calls[-1][1]()
        self.assertIsNone(ov._anticheat_timer_id)
        self.assertFalse(ov._anticheat_red)


if __name__ == "__main__":
    unittest.main()