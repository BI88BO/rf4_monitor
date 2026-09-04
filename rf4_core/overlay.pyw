"""RF4 来鱼浮窗提醒

监听 RF4 Monitor 的 SQLite 事件桥，来鱼时在屏幕角落弹出透明置顶浮窗，
入护后消失。可按住鼠标拖动到任意位置，位置会自动记忆。
"""
import json
import math
import re
import sqlite3
import sys
import time
import tkinter as tk
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = PACKAGE_DIR.parent
if getattr(sys, "frozen", False):
    # 打包态：__file__ 指向临时解压区(_MEIPASS)，改用 exe 所在目录，
    # 才能正确读写随 exe 分发的 rf4_overlay_config.json 与鱼种标签。
    BASE_DIR = Path(sys.executable).resolve().parent
CONFIG_FILE = PACKAGE_DIR / "rf4_overlay_config.json"

DEFAULT_DB_PATH = PACKAGE_DIR / "rf4_overlay_events.sqlite3"
WINDOW_WIDTH = 320
WINDOW_HEIGHT = 70

# 字体族解析缓存：首次真实查询后复用，避免每次重绘都调 tkfont.families()
_FONT_FAMILY_CACHE = None


def load_config():
    try:
        data = json.loads(CONFIG_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        data = {}
    return data


def save_config(data):
    existing = load_config()
    existing.update(data)
    try:
        CONFIG_FILE.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def load_fish_labels():
    labels = {}
    path = PACKAGE_DIR / "fish_labels_zh.json"
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return labels
    raw = data.get("labels") if isinstance(data, dict) else None
    if isinstance(raw, dict):
        labels.update(raw)
    return labels


class Overlay:
    # 背景样式
    STYLE_DARK = "dark"
    STYLE_TRANSPARENT = "transparent"
    DEFAULT_STYLE = STYLE_TRANSPARENT
    _STYLES = {STYLE_DARK, STYLE_TRANSPARENT}
    # 遥测信息区最多保留的行数
    MAX_TELEMETRY_ROWS = 4
    # 样式参数：根窗口背景色；画布配色统一用 CANVAS_* 常量
    _STYLE_PARAMS = {
        STYLE_DARK: {"bg": "#101418"},
        STYLE_TRANSPARENT: {"bg": "#101418"},
    }

    CANVAS_BG = "#0F1916"
    CANVAS_TEXT = "#ffd166"
    CANVAS_DIM = "#b39a5a"
    CANVAS_RED = "#FF5252"
    CANVAS_GRAY = "#5c6b64"
    TRANSPARENT_KEY = "#0000FF"
    CORNER_RADIUS = 12
    # 反外挂警告红字状态：object.__new__ 构造(测试)时默认为 False
    _anticheat_red = False
    # 反外挂红字恢复定时器：同一时刻至多一个，新事件会先取消旧的
    _anticheat_timer_id = None
    # 抓包活跃状态：收到任何事件切正常色，15 秒无事件切灰（类默认 True 兼容测试）
    _capture_active = True
    _capture_last_event_ts = 0.0

    @staticmethod
    def font_family() -> str:
        """解析首选字体，仅首次真实查询，之后复用缓存。"""
        global _FONT_FAMILY_CACHE
        if _FONT_FAMILY_CACHE is None:
            try:
                import tkinter.font as tkfont
                if "三极芯片体 超粗" in tkfont.families():
                    _FONT_FAMILY_CACHE = "三极芯片体 超粗"
                else:
                    _FONT_FAMILY_CACHE = "Microsoft YaHei UI"
            except Exception:
                _FONT_FAMILY_CACHE = "Microsoft YaHei UI"
        return _FONT_FAMILY_CACHE

    @staticmethod
    def _reset_font_family_cache():
        """清空字体缓存，仅供测试重新探测 families() 两条路径。"""
        global _FONT_FAMILY_CACHE
        _FONT_FAMILY_CACHE = None

    def _ensure_canvas(self):
        if self.canvas is None:
            canvas = tk.Canvas(
                self.root,
                highlightthickness=0,
                bg=self.TRANSPARENT_KEY,
            )
            canvas.pack(fill="both", expand=True)
            self.canvas = canvas
        return self.canvas

    @staticmethod
    def _round_rect(canvas, x1, y1, x2, y2, r, **kwargs):
        r = min(r, (x2 - x1) // 2, (y2 - y1) // 2)
        pts = [
            x1 + r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1,
        ]
        kwargs.setdefault("smooth", True)
        return canvas.create_polygon(pts, **kwargs)

    def __init__(self, root, db_path):
        self.root = root
        self.db_path = db_path
        self.labels = load_fish_labels()
        self.visible = False
        self._drag_offset = None
        # 按竿号分行显示：key=竿号文本, value=该竿最新状态行
        self._rows = {}
        # 遥测信息区：多条(商店/装备等)，有序，最多保留 MAX_TELEMETRY_ROWS 条
        self._telemetry_rows = {}
        self._telemetry_seq = 0
        self._idle_visible = False
        self.canvas = None
        self._anticheat_red = False
        self._anticheat_timer_id = None
        self._last_seen_id = 0
        self._capture_active = False
        self._capture_last_event_ts = 0.0

        config = self.load_config()
        self.style = config.get("style", config.get("transparent", True) and self.STYLE_TRANSPARENT or self.STYLE_DARK)
        if self.style not in self._STYLES:
            self.style = self.DEFAULT_STYLE
        self._last_cfg_mtime = self._cfg_mtime()
        pos = config.get("position")
        if isinstance(pos, dict) and isinstance(pos.get("x"), (int, float)) and isinstance(pos.get("y"), (int, float)):
            x = int(pos["x"])
            y = int(pos["y"])
        else:
            screen_w = root.winfo_screenwidth()
            x = screen_w - WINDOW_WIDTH - 20
            y = 20
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)

        self._ensure_canvas()
        # 统一应用背景样式(含透明键设置)
        self.apply_style(self.style)

        self._apply_noactivate()
        self._bind_drag(self.root)
        self._bind_drag(self.canvas)

        self._ensure_sqlite_db()
        # 启动时只消费新事件；数据库里已有的都是上一轮运行的历史。
        self._last_seen_id = self._latest_event_id()
        self._refresh_display()
        self.root.after(30, self._poll)
        self.root.after(800, self._poll_config)

    def load_config(self):
        return load_config()

    def _cfg_mtime(self):
        try:
            return CONFIG_FILE.stat().st_mtime
        except OSError:
            return 0.0

    def apply_style(self, style):
        """应用背景样式(深色/透明)，运行时可切换。"""
        params = self._STYLE_PARAMS.get(style)
        if params is None:
            return
        self.style = style
        self.root.configure(bg=params["bg"])
        try:
            self.root.wm_attributes("-transparentcolor", self.TRANSPARENT_KEY)
        except tk.TclError:
            pass
        self._refresh_display()

    def _poll_config(self):
        try:
            mtime = self._cfg_mtime()
            if mtime != self._last_cfg_mtime:
                self._last_cfg_mtime = mtime
                cfg = load_config()
                style = cfg.get("style", cfg.get("transparent", True) and self.STYLE_TRANSPARENT or self.STYLE_DARK)
                if style in self._STYLES:
                    self.apply_style(style)
        finally:
            self.root.after(800, self._poll_config)

    def _apply_noactivate(self):
        try:
            import ctypes

            hwnd = self.root.winfo_id()
            style = ctypes.windll.user32.GetWindowLongW(hwnd, -20)
            ctypes.windll.user32.SetWindowLongW(hwnd, -20, style | 0x08000000 | 0x00000020)
        except Exception:
            pass

    def _bind_drag(self, widget):
        widget.bind("<ButtonPress-1>", self._on_press)
        widget.bind("<B1-Motion>", self._on_drag)
        widget.bind("<ButtonRelease-1>", self._on_release)

    def _on_press(self, event):
        self._drag_offset = (event.x_root - self.root.winfo_x(), event.y_root - self.root.winfo_y())

    def _on_drag(self, event):
        if self._drag_offset is None:
            return
        x = event.x_root - self._drag_offset[0]
        y = event.y_root - self._drag_offset[1]
        self.root.geometry(f"+{x}+{y}")

    def _on_release(self, event):
        self._drag_offset = None
        save_config({"position": {"x": self.root.winfo_x(), "y": self.root.winfo_y()}})

    def _update_row(self, gear_slot, text, clear_after=0):
        if gear_slot:
            self._rows[gear_slot] = text
        else:
            self._rows[""] = text
        self._refresh_display()
        if clear_after > 0:
            self.root.after(clear_after, lambda: self._clear_row(gear_slot, text))

    def _clear_row(self, gear_slot, expected_text):
        # 只有在该行仍显示传入文本时才清除，避免误删更新的状态。
        current = self._rows.get(gear_slot) if gear_slot else self._rows.get("")
        if current == expected_text:
            if gear_slot:
                self._rows.pop(gear_slot, None)
            else:
                self._rows.pop("", None)
            self._refresh_display()

    @staticmethod
    def _rod_sort_key(slot: str) -> tuple:
        # 竿号按数字排序(1号杆→2号杆→3号杆)；非竿号行排最后。
        match = re.match(r"^(\d+)号杆$", slot or "")
        if match:
            return (0, int(match.group(1)))
        return (1, 0)

    @staticmethod
    def _fight_row_color(text: str, default: str) -> str:
        # 力竭判定：行内唯一的百分数即体力，≤0 变红（兼容新旧两种行格式）。
        match = re.search(r"(\d+)\s*%", text)
        if match and int(match.group(1)) <= 0:
            return "#ff5252"
        return default

    _WEIGHT_PART_RE = re.compile(r"重量=\s*([\d.]+)\s*(公斤|克)")
    _BARE_WEIGHT_RE = re.compile(r"([\d.]+)\s*(公斤|克)")

    @classmethod
    def _fmt_weight(cls, value: str, unit: str) -> str:
        if unit == "公斤":
            return value.rstrip("0").rstrip(".") + "kg"
        return value + "g"

    @classmethod
    def _compact_fight_line(cls, text: str) -> str:
        """把搏鱼状态行压缩成单行：`1号杆 ★黑线鳕444g 78% 12.3米`。

        浮窗仅 320px 宽，完整格式(`1号杆 | [达标] 鱼=x 重量=x 克 体力=x% 出线=x米`)
        必然折行 2~3 行，三竿同开时整窗全是文字。解析失败时返回原文。
        """
        m = re.match(r"^(\d+号杆|手持竿)\s*\|\s*", text)
        if not m:
            return text
        slot, body = m.group(1), text[m.end():]
        out = [slot]
        gm = re.search(r"\[([^\]]+)\]", body)
        if gm:
            out.append(f"[{gm.group(1)}]")
        fm = re.search(r"鱼=([^\s]+)", body)
        wm = cls._WEIGHT_PART_RE.search(body)
        if fm:
            fish = fm.group(1)
            wtxt = cls._fmt_weight(wm.group(1), wm.group(2)) if wm else ""
            out.append(fish + wtxt)
        elif wm:
            out.append(cls._fmt_weight(wm.group(1), wm.group(2)))
        sm = re.search(r"体力\s*(\d+)\s*%", body)
        if sm:
            out.append(sm.group(1) + "%")
        dm = re.search(r"出线\s*([\d.]+)米", body)
        if dm:
            out.append(dm.group(1) + "米")
        if len(out) == 1:
            return text
        return " ".join(out)

    _SELF_EVENT_PREFIX = "【我自己】："
    _SELF_PHASE_SUFFIXES = (
        ("挣脱跑了（脱钩）", "脱钩"),
        ("咬钩了", "咬钩"),
        ("过来了", "来鱼"),
        ("入护了", "入护"),
    )

    @classmethod
    def _compact_self_event(cls, text: str) -> str:
        """来鱼/咬钩等事件压成短句：`★蓝鳃太阳鱼1.55kg 来鱼`。失败返回原文。"""
        if not text.startswith(cls._SELF_EVENT_PREFIX):
            return text
        body = text[len(cls._SELF_EVENT_PREFIX):]
        grade = ""
        gm = re.match(r"\[([^\]]+)\]\s*", body)
        if gm:
            grade = f"[{gm.group(1)}]"
            body = body[gm.end():]
        phase = ""
        for pat, tag in cls._SELF_PHASE_SUFFIXES:
            if body.endswith(pat):
                body = body[: -len(pat)]
                phase = tag
                break
        else:
            if body.startswith("放生"):
                phase = "放生"
                body = body[len("放生了"):].lstrip()
        body = body.strip()
        if body.startswith("有"):
            body = body[1:].strip()
        wm = cls._BARE_WEIGHT_RE.search(body)
        name, wtxt = body.strip(), ""
        if wm:
            wtxt = cls._fmt_weight(wm.group(1), wm.group(2))
            name = (body[: wm.start()] + body[wm.end():]).strip()
        core = f"{grade} {name}{wtxt}".strip() if grade else f"{name}{wtxt}".strip()
        if phase and core:
            return f"{core} {phase}"
        if core:
            return core
        return phase or text

    def _show_telemetry(self, text):
        # 遥测信息独立成区：新消息追加，不覆盖旧的；超限时丢弃最旧。
        self._telemetry_seq += 1
        self._telemetry_rows[self._telemetry_seq] = text
        if len(self._telemetry_rows) > self.MAX_TELEMETRY_ROWS:
            oldest = next(iter(self._telemetry_rows))
            self._telemetry_rows.pop(oldest, None)
        seq = self._telemetry_seq
        self._refresh_display()
        self.root.after(3000, lambda: self._clear_telemetry(seq, text))

    def _clear_telemetry(self, seq, expected_text):
        if self._telemetry_rows.get(seq) == expected_text:
            self._telemetry_rows.pop(seq, None)
            self._refresh_display()

    def _refresh_display(self):
        lines = self._lines_for_display()
        need_h = self._content_height(lines)
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        self.root.geometry(f"{WINDOW_WIDTH}x{need_h}+{x}+{y}")
        self._draw(width=WINDOW_WIDTH, height=need_h)
        self._show()

    def _lines_for_display(self):
        lines = [self._rows[key] for key in sorted(self._rows, key=self._rod_sort_key)]
        for seq, text in self._telemetry_rows.items():
            lines.append(text)
        if not lines:
            lines = ["来鱼提示 · 待机中"]
        return lines

    def _any_exhausted(self, lines) -> bool:
        return any(
            Overlay._fight_row_color(text, self.CANVAS_TEXT).lower() == self.CANVAS_RED.lower()
            for text in lines
        )

    def _is_transparent(self) -> bool:
        """透明模式：只画文字、不画玻璃卡；画布背景即透明键 #0000FF。"""
        return self.style == self.STYLE_TRANSPARENT

    def _row_height(self) -> int:
        """单行文本高度(像素)：用与渲染一致的 bold 字体度量。"""
        try:
            import tkinter.font as tkfont

            f = tkfont.Font(self.root, family=Overlay.font_family(), size=13, weight="bold")
            return f.metrics("linespace") + 4
        except Exception:
            return 28

    def _draw(self, *, width, height):
        canvas = self._ensure_canvas()
        canvas.delete("all")
        # 非透明模式画玻璃卡(圆角背景+内侧描边+HUD 装饰线)；透明模式跳过，
        # 画布背景是透明键 #0000FF，只有文字浮于桌面。
        if not self._is_transparent():
            r = self.CORNER_RADIUS
            Overlay._round_rect(canvas, 1, 1, width - 2, height - 2, r,
                                fill=self.CANVAS_BG)
        # 第一块：竿号/搏鱼行(按竿号排序，主色)；第二块：遥测/待机行(降暗色)。
        rod_lines = [self._rows[key] for key in sorted(self._rows, key=self._rod_sort_key)]
        dim_lines = list(self._telemetry_rows.values())
        if not rod_lines and not dim_lines:
            dim_lines = ["来鱼提示 · 待机中"]
        # 反外挂红字优先：直接整块红字，跳过力竭判断(避免无效计算)
        if not self._capture_active:
            rod_color = self.CANVAS_GRAY
        elif self._anticheat_red:
            rod_color = self.CANVAS_RED
        else:
            rod_color = self.CANVAS_RED if self._any_exhausted(rod_lines) else self.CANVAS_TEXT
        if rod_lines:
            canvas.create_text(
                16, 14,
                text="\n".join(rod_lines),
                anchor="nw",
                font=(Overlay.font_family(), 13, "bold"),
                fill=rod_color,
                width=width - 32,
                justify="left",
            )
        if dim_lines:
            canvas.create_text(
                16, 14 + len(rod_lines) * self._row_height(),
                text="\n".join(dim_lines),
                anchor="nw",
                font=(Overlay.font_family(), 13, "bold"),
                fill=self.CANVAS_GRAY if not self._capture_active else self.CANVAS_DIM,
                width=width - 32,
                justify="left",
            )

    def _content_height(self, lines):
        """按换行数估算需求高度：长消息按实际换行行数计算，避免被裁切。"""
        try:
            import tkinter.font as tkfont

            wrap_px = WINDOW_WIDTH - 32
            f = tkfont.Font(self.root, family=Overlay.font_family(), size=13, weight="bold")
            row_h = f.metrics("linespace") + 4
            total = 0
            for line in lines:
                visual = max(1, math.ceil(f.measure(line) / max(wrap_px, 1)))
                total += visual * row_h
            # 顶部 + 底部 padding(padx/pady) + 边框余量
            return max(40, total + 40)
        except Exception:
            return 40 + 28 * len(lines)

    def _show_self_event(self, gear_slot, text, clear_after=0):
        # 直接使用与日志一致的整行文本（已含【我自己】与等级前缀），按竿号分行。
        if not text:
            return
        self._update_row(gear_slot or "", text, clear_after)

    def _show_generic(self, text):
        # 频道鱼获/公共聊天/遥测等"信息类"统一进遥测区，独立分行显示。
        self._show_telemetry(text)

    def _show_anticheat(self, text):
        # 反外挂警告：整窗红字显示 8 秒后恢复默认配色（原 Label 变色迁移到 canvas 文本色）。
        # 连续事件先取消上一个恢复定时器，避免旧计时提前清掉新警告的红字。
        self._anticheat_red = True
        self._show_telemetry(text)
        if self._anticheat_timer_id is not None:
            try:
                self.root.after_cancel(self._anticheat_timer_id)
            except Exception:
                pass
        self._anticheat_timer_id = self.root.after(8000, lambda: self._clear_anticheat_red())

    def _clear_anticheat_red(self):
        self._anticheat_timer_id = None
        if self._anticheat_red:
            self._anticheat_red = False
            self._refresh_display()

    def _reset_to_idle(self):
        self._rows.clear()
        self._telemetry_rows.clear()
        self._refresh_display()

    def _hide(self):
        if self.visible:
            self.root.withdraw()
            self.visible = False

    def _show(self):
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.visible = True

    def _ensure_sqlite_db(self):
        try:
            con = sqlite3.connect(str(self.db_path), timeout=1.0)
            try:
                con.execute("PRAGMA busy_timeout = 1000")
                con.execute(
                    "CREATE TABLE IF NOT EXISTS overlay_events ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "ts REAL NOT NULL,"
                    "event_type TEXT NOT NULL,"
                    "payload TEXT NOT NULL"
                    ")"
                )
                con.execute(
                    "CREATE INDEX IF NOT EXISTS idx_overlay_events_ts "
                    "ON overlay_events(ts)"
                )
                con.commit()
            finally:
                con.close()
        except (OSError, sqlite3.Error):
            pass

    def _latest_event_id(self) -> int:
        try:
            con = sqlite3.connect(str(self.db_path), timeout=1.0)
            try:
                con.execute("PRAGMA busy_timeout = 1000")
                row = con.execute("SELECT MAX(id) FROM overlay_events").fetchone()
                return int(row[0] or 0)
            finally:
                con.close()
        except (OSError, sqlite3.Error):
            return 0

    def _poll(self):
        try:
            con = sqlite3.connect(str(self.db_path), timeout=1.0)
            try:
                con.execute("PRAGMA busy_timeout = 1000")
                rows = con.execute(
                    "SELECT id, payload FROM overlay_events WHERE id > ? ORDER BY id",
                    (self._last_seen_id,),
                ).fetchall()
                for row_id, payload in rows:
                    try:
                        self._handle_event_payload(payload)
                    except Exception:
                        pass
                if rows:
                    # 游标推进到最新事件的自增 id（id 全局单调，不受 bridge 重启影响）。
                    self._last_seen_id = rows[-1][0]
                    self._on_capture_alive()
            finally:
                con.close()
        except (OSError, sqlite3.Error):
            pass
        finally:
            self._check_capture_timeout()
            self.root.after(30, self._poll)

    def _on_capture_alive(self):
        self._capture_last_event_ts = time.time()
        if not self._capture_active:
            self._capture_active = True
            try:
                self._refresh_display()
            except AttributeError:
                pass

    def _check_capture_timeout(self):
        if self._capture_active and time.time() - self._capture_last_event_ts > 15:
            self._capture_active = False
            try:
                self._refresh_display()
            except AttributeError:
                pass

    def _handle_event_payload(self, payload):
        try:
            event = json.loads(payload)
        except (UnicodeDecodeError, ValueError):
            return
        name = event.get("event")
        gear_slot = event.get("gear_slot") or ""
        text = event.get("text") or ""
        # 来鱼/咬钩保持到下一条事件(咬钩/搏鱼/结算/脱钩)覆盖，不再定时消失；
        # 入护/脱钩/放生维持 3 秒后消失。
        if name in ("fish_kept", "fish_escaped", "fish_released"):
            clear_after = 3000
        else:
            clear_after = 0
        if name == "reset":
            self._reset_to_idle()
        elif name in ("fish_incoming", "fish_bitten", "fish_kept", "fish_escaped", "fish_released"):
            self._show_self_event(gear_slot, self._compact_self_event(text), clear_after)
        elif name in ("fish_catch", "chat"):
            self._show_generic(text)
        elif name == "telemetry":
            if not text:
                return
            # 竿行/手持竿就地更新并压缩成单行；其余进遥测区通用显示。
            match = re.match(r"^(\d+号杆|手持竿) ", text)
            if match:
                self._update_row(match.group(1), self._compact_fight_line(text))
            else:
                self._show_generic(text)
        elif name == "anticheat":
            self._show_anticheat(text)


def main():
    config = load_config()
    db_path = Path(config.get("db_path", str(DEFAULT_DB_PATH)))
    root = tk.Tk()
    root.title("来鱼提示")
    Overlay(root, db_path)
    root.mainloop()


if __name__ == "__main__":
    main()
