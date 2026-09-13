"""deskmon_overlay：玻璃拟态绘制与紧凑化测试。"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

_OVERLAY_PATH = Path(__file__).resolve().parents[2] / "overlay.pyw"
_spec = importlib.util.spec_from_file_location("rf4_core.overlay", _OVERLAY_PATH)
overlay_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(overlay_mod)
Overlay = overlay_mod.Overlay


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
        self.assertEqual(Overlay.CANVAS_BG, "#151B23")
        self.assertEqual(Overlay.CANVAS_BORDER, "#2C3542")
        self.assertEqual(Overlay.CANVAS_TEXT, "#ffd166")
        self.assertEqual(Overlay.CANVAS_DIM, "#b39a5a")
        self.assertEqual(Overlay.CORNER_RADIUS, 10)

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
            "create_text": lambda self, *a, **k: (created.append(("text", {**({"x": a[0], "y": a[1]} if len(a) >= 2 else {}), **k})) or 3),
        })()
        ov.canvas = canvas
        ov._ensure_canvas = lambda: canvas
        ov._content_height = lambda lines: 60
        ov._show = lambda: None
        ov.created = created
        ov.root = SimpleNamespace()
        ov._capture_active = True
        return ov

    def test_draw_renders_filled_rounded_card_and_text(self) -> None:
        ov = self._overlay()
        ov._draw(width=320, height=60)
        kinds = [c[0] for c in ov.created]
        self.assertIn("polygon", kinds)  # 圆角卡片背景
        self.assertNotIn("line", kinds)  # 无独立描边/装饰线
        self.assertIn("text", kinds)     # 文本
        bg = [k for k in ov.created if k[0] == "polygon"]
        self.assertTrue(all(k[1].get("fill") == "#151B23" for k in bg))
        self.assertTrue(all(k[1].get("outline") == Overlay.CANVAS_BORDER for k in bg))

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
        # 第二块 y = 顶部内边距 + 竿行数 × 行高(测试环境无 Tk，行高回退 20)
        self.assertEqual(texts[1][1]["y"], Overlay.PAD_Y + 1 * 20)

    def test_idle_fallback_line_is_dim(self) -> None:
        ov = self._overlay()
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._draw(width=320, height=60)
        texts = [k for k in ov.created if k[0] == "text"]
        self.assertEqual(len(texts), 1)
        self.assertEqual(texts[0][1]["fill"], Overlay.CANVAS_DIM)
        self.assertEqual(texts[0][1]["text"], "来鱼提示 · 待机中")

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


class OverlayGeometryTests(unittest.TestCase):
    def test_refresh_display_sets_size_without_position(self) -> None:
        # 回归：窗口首次映射前 winfo_x/y 返回 (0,0)，若 _refresh_display 拼上
        # "+x+y" 会把记住的位置覆盖成屏幕左上角。必须只设尺寸。
        ov = object.__new__(Overlay)
        calls = []
        ov.root = SimpleNamespace(geometry=lambda spec: calls.append(spec))
        ov._lines_for_display = lambda: ["来鱼提示 · 待机中"]
        ov._content_height = lambda lines, width: 42
        ov._draw = lambda **kwargs: None
        ov._show = lambda: None

        ov._refresh_display()

        self.assertEqual(calls, [f"{overlay_mod.WINDOW_WIDTH}x42"])
        self.assertNotIn("+", calls[0])

    def test_content_width_keeps_min_for_short_and_clamps_long(self) -> None:
        # 待机短句保持最小宽度；超长搏鱼行加宽但不超过上限。
        import tkinter.font as tkfont

        class _FakeFont:
            def __init__(self, *args, **kwargs):
                pass

            def measure(self, text):
                return len(text) * 20

        ov = object.__new__(Overlay)
        ov.root = SimpleNamespace()
        prev = tkfont.Font
        tkfont.Font = _FakeFont
        try:
            short = ov._content_width(["短句"])
            long = ov._content_width(["x" * 100])
        finally:
            tkfont.Font = prev
        self.assertEqual(short, overlay_mod.WINDOW_WIDTH)
        self.assertEqual(long, overlay_mod.WINDOW_MAX_WIDTH)


class OverlayCompactTests(unittest.TestCase):
    """浮窗紧凑化：搏鱼行单行化 + 事件短句化，三竿同开不再满屏折行。"""

    def test_compact_fight_full(self) -> None:
        text = "1号杆 | [稀有★] 鱼=黑线鳕 重量=444 克 体力 78% 出线 12.3米"
        self.assertEqual(
            Overlay._compact_fight_line(text),
            "1号杆 [稀有★] 黑线鳕444g 78% 12.3米",
        )

    def test_compact_fight_keeps_depth(self) -> None:
        text = "1号杆 | [稀有★] 鱼=黑线鳕 重量=444 克 体力 78% 深4.5米 出线 12.3米"
        self.assertEqual(
            Overlay._compact_fight_line(text),
            "1号杆 [稀有★] 黑线鳕444g 78% 深4.5米 12.3米",
        )

    def test_compact_fight_kilograms_trim_zeros(self) -> None:
        text = "2号杆 | 鱼=隆头鳕 重量=1.250 公斤 体力 80% 出线 18.6米"
        self.assertEqual(
            Overlay._compact_fight_line(text),
            "2号杆 隆头鳕1.25kg 80% 18.6米",
        )

    def test_compact_fight_super_rare_symbol(self) -> None:
        text = "3号杆 | [超级稀有◆] 鱼=蓝鳃太阳鱼 重量=6.030 公斤 体力 55% 出线 40.02米"
        self.assertEqual(
            Overlay._compact_fight_line(text),
            "3号杆 [超级稀有◆] 蓝鳃太阳鱼6.03kg 55% 40.0米",
        )

    def test_compact_fight_without_fish_meta(self) -> None:
        self.assertEqual(
            Overlay._compact_fight_line("3号杆 | 体力 78% 出线 12.3米"),
            "3号杆 78% 12.3米",
        )

    def test_compact_fight_minimal_unchanged(self) -> None:
        # 解析不到任何内容时保持原样。
        self.assertEqual(Overlay._compact_fight_line("1号杆"), "1号杆")

    def test_compact_self_event_incoming(self) -> None:
        text = "【我自己】：[稀有★] 有蓝鳃太阳鱼 1.553 公斤 过来了"
        self.assertEqual(
            Overlay._compact_self_event(text),
            "[稀有★] 蓝鳃太阳鱼1.553kg 来鱼",
        )

    def test_compact_self_event_bitten(self) -> None:
        text = "【我自己】：[达标] 黑线鳕 444 克 咬钩了"
        self.assertEqual(Overlay._compact_self_event(text), "[达标] 黑线鳕444g 咬钩")

    def test_compact_fight_grade_preserved_verbatim(self) -> None:
        # 四档品质文字原样保留（用户要求：几个字没影响）。
        for grade in ("不达标", "达标", "稀有★", "超级稀有◆"):
            text = f"1号杆 | [{grade}] 鱼=拟鲤 重量=120 克 体力 100% 出线 4.2米"
            self.assertEqual(
                Overlay._compact_fight_line(text),
                f"1号杆 [{grade}] 拟鲤120g 100% 4.2米",
            )

    def test_compact_self_event_released(self) -> None:
        text = "【我自己】：[超级稀有◆] 放生了 鲤鱼"
        self.assertEqual(Overlay._compact_self_event(text), "[超级稀有◆] 鲤鱼 放生")

    def test_compact_self_event_escaped(self) -> None:
        text = "【我自己】：鲤鱼 2.0 公斤 挣脱跑了（脱钩）"
        self.assertEqual(Overlay._compact_self_event(text), "鲤鱼2kg 脱钩")

    def test_compact_self_event_plain_release(self) -> None:
        self.assertEqual(Overlay._compact_self_event("【我自己】：放生了"), "放生")

    def test_compact_self_event_fallback_keeps_original(self) -> None:
        text = "完全不是事件格式的文本"
        self.assertEqual(Overlay._compact_self_event(text), text)

    def test_incoming_and_bitten_persist_until_next_event(self) -> None:
        ov = object.__new__(Overlay)
        after_calls: list[tuple] = []
        ov.root = SimpleNamespace(after=lambda delay, fn: after_calls.append(delay))
        ov._rows = {}
        ov._refresh_display = lambda: None
        payload = json.dumps(
            {"event": "fish_incoming", "gear_slot": "2号杆",
             "text": "【我自己】：有鲤鱼 2.0 公斤 过来了"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(ov._rows.get("2号杆"), "鲤鱼2kg 来鱼")
        self.assertNotIn(8000, after_calls)

    def test_kept_still_clears_after_3s(self) -> None:
        ov = object.__new__(Overlay)
        after_calls: list[tuple] = []
        ov.root = SimpleNamespace(after=lambda delay, fn: after_calls.append(delay))
        ov._rows = {}
        ov._refresh_display = lambda: None
        payload = json.dumps(
            {"event": "fish_kept", "gear_slot": "1号杆",
             "text": "【我自己】：黑线鳕 444 克 入护了"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(ov._rows.get("1号杆"), "黑线鳕444g 入护")
        self.assertIn(3000, after_calls)


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


class OverlaySuspendDisplayTests(unittest.TestCase):
    def test_suspend_status_appended_to_display_lines(self) -> None:
        ov = object.__new__(Overlay)
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._suspend_loop = SimpleNamespace(status_text=lambda: "已挂起 119")
        self.assertEqual(ov._lines_for_display(), ["来鱼提示 · 待机中", "已挂起 119"])

    def test_suspend_status_uses_red_even_without_capture(self) -> None:
        ov = object.__new__(Overlay)
        ov.style = Overlay.STYLE_TRANSPARENT
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._suspend_loop = SimpleNamespace(status_text=lambda: "已挂起 119")
        ov._capture_active = False
        created: list[tuple] = []
        canvas = type("C", (), {
            "delete": lambda self, tag: None,
            "create_text": lambda self, *a, **k: created.append(k) or 1,
        })()
        ov.canvas = canvas
        ov._ensure_canvas = lambda: canvas
        ov._draw(width=320, height=60)
        self.assertEqual(created[0]["fill"], Overlay.CANVAS_RED)
        self.assertEqual(created[0]["text"], "已挂起 119")

    def test_suspend_countdown_change_refreshes_display(self) -> None:
        texts = ["已挂起 60", "已挂起 59"]
        ov = object.__new__(Overlay)
        ov._suspend_loop = SimpleNamespace(
            tick=lambda: texts.pop(0),
            status_text=lambda: texts[0],
        )
        refresh_calls: list[bool] = []
        ov._refresh_display = lambda: refresh_calls.append(True)
        ov._update_suspend_loop()
        self.assertEqual(ov._suspend_loop.status_text(), "已挂起 59")
        self.assertEqual(refresh_calls, [True])

    def test_suspend_countdown_change_between_polls_refreshes_display(self) -> None:
        # F8 后立刻画 60；下一次轮询读取到的可能已经是 59。
        # 必须和上次画出的状态比较，否则 60 会一直挂到状态机切换。
        ov = object.__new__(Overlay)
        ov._last_suspend_status = "已挂起 60"
        ov._suspend_loop = SimpleNamespace(
            tick=lambda: None,
            status_text=lambda: "已挂起 59",
        )
        refresh_calls: list[bool] = []
        ov._refresh_display = lambda: refresh_calls.append(True)
        ov._update_suspend_loop()
        self.assertEqual(ov._last_suspend_status, "已挂起 59")
        self.assertEqual(refresh_calls, [True])

    def test_failed_toggle_shows_persistent_error(self) -> None:
        ov = object.__new__(Overlay)
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._suspend_loop = SimpleNamespace(
            suspended=False,
            toggle=lambda: False,
            status_text=lambda: "未找到 rf4_x64.exe 或挂起失败",
        )
        refresh_calls: list[bool] = []
        ov._refresh_display = lambda: refresh_calls.append(True)
        ov._toggle_suspend()
        self.assertEqual(
            ov._lines_for_display(),
            ["来鱼提示 · 待机中", "未找到 rf4_x64.exe 或挂起失败"],
        )
        self.assertEqual(refresh_calls, [True])

    def test_hotkey_registration_failure_persists(self) -> None:
        ov = object.__new__(Overlay)
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._suspend_loop = SimpleNamespace()
        refresh_calls: list[bool] = []
        ov._refresh_display = lambda: refresh_calls.append(True)
        real_hotkey = overlay_mod.GlobalHotkey
        overlay_mod.GlobalHotkey = lambda hotkey: SimpleNamespace(start=lambda: False)
        try:
            ov._start_suspend_hotkey()
        finally:
            overlay_mod.GlobalHotkey = real_hotkey
        self.assertIsNone(ov._hotkey)
        self.assertEqual(
            ov._lines_for_display(),
            ["来鱼提示 · 待机中", "F8 热键注册失败，可能已被占用"],
        )
        self.assertEqual(refresh_calls, [True])

    def test_fish_row_and_suspend_countdown_are_shown_together(self) -> None:
        ov = object.__new__(Overlay)
        ov._rows = {"1号杆": "黑线鳕444g 咬钩"}
        ov._telemetry_rows = {}
        ov._suspend_loop = SimpleNamespace(status_text=lambda: "已挂起 60")
        refresh_calls: list[bool] = []
        ov._refresh_display = lambda: refresh_calls.append(True)
        ov.root = SimpleNamespace(after=lambda delay, fn: None)
        payload = json.dumps(
            {"event": "fish_bitten", "gear_slot": "1号杆",
             "text": "【我自己】：黑线鳕 444 克 咬钩了"},
            ensure_ascii=False,
        )
        ov._handle_event_payload(payload)
        self.assertEqual(
            ov._lines_for_display(),
            ["黑线鳕444g 咬钩", "已挂起 60"],
        )
        self.assertEqual(len(refresh_calls), 1)


class OverlayCaptureStateTests(unittest.TestCase):
    def test_capture_status_latches_after_first_event(self) -> None:
        ov = object.__new__(Overlay)
        ov._capture_active = False
        refresh_calls = []
        ov._refresh_display = lambda: refresh_calls.append(True)
        ov._on_capture_alive()
        ov._on_capture_alive()
        self.assertTrue(ov._capture_active)
        self.assertEqual(len(refresh_calls), 1)

    def test_idle_fallback_uses_gray_before_capture(self) -> None:
        ov = object.__new__(Overlay)
        ov.style = Overlay.STYLE_TRANSPARENT
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._capture_active = False
        created: list[tuple] = []
        canvas = type("C", (), {
            "delete": lambda self, tag: None,
            "create_text": lambda self, *a, **k: created.append(k) or 1,
        })()
        ov.canvas = canvas
        ov._ensure_canvas = lambda: canvas
        ov._draw(width=320, height=60)
        self.assertEqual(created[0]["fill"], Overlay.CANVAS_GRAY)
