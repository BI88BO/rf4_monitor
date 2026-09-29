"""RF4 来鱼浮窗提醒

监听 RF4 Monitor 的 SQLite 事件桥，来鱼时在屏幕角落弹出透明置顶浮窗，
入护后消失。可按住鼠标拖动到任意位置，位置会自动记忆。
"""
import json
import math
import os
import re
import sqlite3
import sys
import threading
import time
import tkinter as tk
from pathlib import Path

try:
    from .process_control import (
        GlobalHotkey,
        ProcessSuspender,
        SuspendConfig,
        SuspendLoop,
    )
except ImportError:
    from process_control import (
        GlobalHotkey,
        ProcessSuspender,
        SuspendConfig,
        SuspendLoop,
    )

PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = PACKAGE_DIR.parent
if getattr(sys, "frozen", False):
    # 打包态：__file__ 指向临时解压区(_MEIPASS)，改用 exe 所在目录，
    # 才能正确读写随 exe 分发的 rf4_overlay_config.json 与鱼种标签。
    BASE_DIR = Path(sys.executable).resolve().parent
CONFIG_FILE = PACKAGE_DIR / "rf4_overlay_config.json"

DEFAULT_DB_PATH = PACKAGE_DIR / "rf4_overlay_events.sqlite3"
ROWS_FILE = PACKAGE_DIR / "rf4_overlay_rows.json"
# 重启浮窗后恢复竿行的最大间隔：太久之前的竿行不再可信（可能已收竿）。
ROWS_RESTORE_MAX_AGE_SECONDS = 10 * 60.0
WINDOW_WIDTH = 260
WINDOW_MAX_WIDTH = 340
WINDOW_HEIGHT = 42

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


def load_rows():
    """恢复上次退出时的竿行（限期内有效），避免重启浮窗后空闲竿从浮窗消失。"""
    try:
        data = json.loads(ROWS_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    saved_at = data.get("saved_at")
    if not isinstance(saved_at, (int, float)) or time.time() - saved_at > ROWS_RESTORE_MAX_AGE_SECONDS:
        return {}
    rows = data.get("rows")
    if not isinstance(rows, dict):
        return {}
    return {str(key): value for key, value in rows.items() if isinstance(value, str)}


def save_rows(rows):
    try:
        ROWS_FILE.write_text(
            json.dumps({"saved_at": time.time(), "rows": rows}, ensure_ascii=False),
            encoding="utf-8",
        )
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

    CANVAS_BG = "#151B23"
    CANVAS_BORDER = "#2C3542"
    CANVAS_TEXT = "#ffd166"
    CANVAS_DIM = "#b39a5a"
    CANVAS_RED = "#FF5252"
    CANVAS_GRAY = "#6B7684"
    TRANSPARENT_KEY = "#0000FF"
    CORNER_RADIUS = 10
    FONT_SIZE = 11
    PAD_X = 12
    PAD_Y = 10
    # 事件轮询：一 tick 内分批抽干积压，整批只重绘一次；读库出错时退避重连，
    # 避免每 30ms 重连并重建表把 Tk 主线程堵死（表现为浮窗卡一下才跳更新）。
    POLL_INTERVAL_MS = 30
    POLL_BATCH_LIMIT = 200
    POLL_MAX_BATCHES = 10
    POLL_BACKOFF_MAX_MS = 1000
    # 空闲多久换一次连接：事件库被监控侧重建后，旧句柄再也读不到新事件。
    POLL_IDLE_REOPEN_SECONDS = 5.0
    # 挂起状态机节拍：跑在自己的线程上，与事件轮询无关，见 Overlay._suspend_worker。
    SUSPEND_TICK_INTERVAL_MS = 20
    SUSPEND_THREAD_JOIN_TIMEOUT_SECONDS = 1.0
    # 来鱼/咬钩时自动解除挂起的事件名
    # 挂起中的来鱼流程：来鱼解冻，咬钩自动冻回去，鱼结束/换会话就取消待命。
    SUSPEND_FISH_FLOW = {
        "fish_incoming": ("release", "来鱼"),
        "fish_bitten": ("freeze", "咬钩"),
        "fish_kept": ("disarm", ""),
        "fish_escaped": ("disarm", ""),
        "fish_released": ("disarm", ""),
        "reset": ("disarm", ""),
        "session_end": ("disarm", ""),
    }
    # 反外挂警告红字状态：object.__new__ 构造(测试)时默认为 False
    _anticheat_red = False
    # 反外挂红字恢复定时器：同一时刻至多一个，新事件会先取消旧的
    _anticheat_timer_id = None
    # 抓包状态锁存：启动后未收到事件为灰色，收到事件后保持正常色
    _capture_active = False
    # 画布：object.__new__ 构造(测试)时可能还没建，测量高度要能退回估算
    canvas = None
    # 一批事件只在抽干后重绘一次、落盘一次。默认值供 object.__new__ 构造(测试)使用。
    _defer_refresh = False
    _refresh_pending = False
    _rows_dirty = False
    _last_seen_id = 0
    _poll_error_streak = 0
    _sqlite_opened_ts = 0.0
    # 临时结果行(入护/脱钩/放生)闪现结束后要恢复的常驻文本，key=竿号行键。
    _row_restore = None
    # 挂起状态：object.__new__ 构造(测试)时默认关闭
    _suspend_loop = None
    _hotkey = None
    _suspend_error = None
    _last_suspend_status = ""
    _suspend_thread = None
    _suspend_stop = None
    # 默认配置仅供 object.__new__ 构造(测试)读取开关用
    _suspend_config = SuspendConfig()

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
        # 按竿号分行显示：key=竿号文本, value=该竿最新状态行。
        # 启动时恢复上次的竿行，否则重启浮窗后已抛竿的空闲竿会消失。
        self._rows = load_rows()
        # 遥测信息区：多条(商店/装备等)，有序，最多保留 MAX_TELEMETRY_ROWS 条
        self._telemetry_rows = {}
        self._telemetry_seq = 0
        self._idle_visible = False
        self.canvas = None
        self._sqlite_con = None
        self._anticheat_red = False
        self._anticheat_timer_id = None
        self._last_seen_id = 0
        self._capture_active = False
        self._defer_refresh = False
        self._refresh_pending = False
        self._rows_dirty = False
        self._poll_error_streak = 0
        self._sqlite_opened_ts = 0.0
        self._suspend_config = SuspendConfig.load()
        self._suspend_loop = None
        self._hotkey = None
        self._suspend_error = None
        self._last_suspend_status = ""
        self._suspend_thread = None
        self._suspend_stop = None
        if self._suspend_config.enabled and os.name == "nt":
            self._suspend_loop = SuspendLoop(
                ProcessSuspender(self._suspend_config.process_names),
                self._suspend_config,
            )

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
        self.root.after(self.POLL_INTERVAL_MS, self._poll)
        self.root.after(800, self._poll_config)
        self._start_suspend_hotkey()
        self._start_suspend_engine()
        self.root.protocol("WM_DELETE_WINDOW", self.destroy)

    def destroy(self):
        if self._rows_dirty:
            save_rows(self._rows)
        self._close_suspend()
        self._close_sqlite()
        self.root.destroy()

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

    def _row_restore_map(self) -> dict:
        if self._row_restore is None:
            self._row_restore = {}
        return self._row_restore

    def _update_row(self, gear_slot, text, clear_after=0):
        key = gear_slot or ""
        if clear_after > 0:
            # 记下当前常驻文本(setdefault：连续两条临时行保留最早那条的原文)。
            self._row_restore_map().setdefault(key, self._rows.get(key, ""))
        else:
            self._row_restore_map().pop(key, None)
        self._rows[key] = text
        self._rows_dirty = True
        self._refresh_display()
        if clear_after > 0:
            self.root.after(clear_after, lambda: self._clear_row(gear_slot, text))

    def schedule(self, delay_ms, callback):
        """延迟执行 callback，返回 after ID（可传给 after_cancel 取消）。"""
        return self.root.after(delay_ms, callback)

    def _clear_row(self, gear_slot, expected_text):
        # 只有在该行仍显示传入文本时才清除，避免误删更新的状态。
        key = gear_slot or ""
        if self._rows.get(key) != expected_text:
            return
        previous = self._row_restore_map().pop(key, "")
        if previous:
            # 闪现结束回到上一条常驻行；直接删行会让这根竿从浮窗消失，
            # 直到下次抛竿才有行（用户看到的"某根杆子信息偶尔不见了"）。
            self._rows[key] = previous
        else:
            self._rows.pop(key, None)
        self._rows_dirty = True
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
    def _fmt_meter(cls, value: str) -> str:
        """深度/出线统一保留 1 位小数：20.482→20.5，2.473→2.5。"""
        try:
            return f"{float(value):.1f}"
        except ValueError:
            return value

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
        depth_m = re.search(r"深\s*([\d.]+)米", body)
        if depth_m:
            out.append("深" + cls._fmt_meter(depth_m.group(1)) + "米")
        dm = re.search(r"出线\s*([\d.]+)米", body)
        if dm:
            out.append(cls._fmt_meter(dm.group(1)) + "米")
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
        # 信息缺失的兜底句（有鱼过来了/有鱼入护了）整体去掉"有鱼"前缀。
        if body.startswith("有鱼"):
            body = body[2:].strip()
        elif body.startswith("有"):
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
        if self._defer_refresh:
            # 一批事件里逐条重绘会把 Tk 主线程占满，抽干后统一画一次。
            self._refresh_pending = True
            return
        if self._rows_dirty:
            self._rows_dirty = False
            save_rows(self._rows)
        lines = self._lines_for_display()
        width = self._content_width(lines)
        height = self._content_height(lines, width)
        # 只设置尺寸、不带位置：Tk 会保留当前/已请求的位置。若在这里读
        # winfo_x/y 重新拼 geometry，窗口首次映射前它们还是 (0,0)，会把
        # 配置里记住的位置覆盖成屏幕左上角。
        self.root.geometry(f"{width}x{height}")
        self._draw(width=width, height=height)
        measured = self._measured_height(height)
        if measured > height:
            # 估算按"字符宽度/可用宽度"折算，Tk 实际按词边界换行，长搏鱼行会
            # 多折一行；高度不够时下面一行就被窗口下沿裁掉半行，所以改用实测值。
            self.root.geometry(f"{width}x{measured}")
            self._draw(width=width, height=measured)
        self._show()

    def _text_bottom(self, canvas, tags, fallback: int) -> int:
        """读文字块实测底部；画布还不可用(测试/未建画布)时退回估算值。"""
        measure = getattr(canvas, "bbox", None)
        if measure is None:
            return fallback
        try:
            box = measure(tags)
        except tk.TclError:
            return fallback
        if not box:
            return fallback
        return int(math.ceil(box[3]))

    def _measured_height(self, fallback: int) -> int:
        canvas = getattr(self, "canvas", None)
        if canvas is None:
            return fallback
        return max(fallback, self._text_bottom(canvas, "body", fallback - self.PAD_Y) + self.PAD_Y)

    def _content_width(self, lines):
        """按最长行计算窗口宽度：待机保持紧凑，长搏鱼行最多加宽到上限，
        让鱼名/体力/深度/出线尽量在两行内显示完。"""
        try:
            import tkinter.font as tkfont

            f = tkfont.Font(self.root, family=Overlay.font_family(), size=self.FONT_SIZE, weight="bold")
            longest = max((f.measure(line) for line in lines if line), default=0)
            # +4 余量：Tk 换行按词边界判断，宽度贴边时可能多折一行。
            needed = longest + self.PAD_X * 2 + 4
            return max(WINDOW_WIDTH, min(WINDOW_MAX_WIDTH, needed))
        except Exception:
            return WINDOW_WIDTH

    def _lines_for_display(self):
        lines = [self._rows[key] for key in sorted(self._rows, key=self._rod_sort_key)]
        for seq, text in self._telemetry_rows.items():
            lines.append(text)
        if not lines:
            lines = ["来鱼提示 · 待机中"]
        status = self._suspend_status_line()
        if status:
            lines.append(status)
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

            f = tkfont.Font(self.root, family=Overlay.font_family(), size=self.FONT_SIZE, weight="bold")
            return f.metrics("linespace") + 3
        except Exception:
            return 20

    def _draw(self, *, width, height):
        canvas = self._ensure_canvas()
        canvas.delete("all")
        # 非透明模式画玻璃卡(圆角背景+描边)；透明模式跳过，
        # 画布背景是透明键 #0000FF，只有文字浮于桌面。
        if not self._is_transparent():
            r = self.CORNER_RADIUS
            Overlay._round_rect(canvas, 1, 1, width - 2, height - 2, r,
                                fill=self.CANVAS_BG, outline=self.CANVAS_BORDER)
        # 第一块：竿号/搏鱼行(按竿号排序，主色)；第二块：遥测/待机行(降暗色)。
        rod_lines = [self._rows[key] for key in sorted(self._rows, key=self._rod_sort_key)]
        dim_lines = list(self._telemetry_rows.values())
        suspend_line = self._suspend_status_line()
        if suspend_line:
            rod_lines.append(suspend_line)
        if not rod_lines and not dim_lines:
            dim_lines = ["来鱼提示 · 待机中"]
        # 反外挂红字优先：直接整块红字，跳过力竭判断(避免无效计算)
        if suspend_line:
            rod_color = self.CANVAS_RED
        elif not self._capture_active:
            rod_color = self.CANVAS_GRAY
        elif self._anticheat_red:
            rod_color = self.CANVAS_RED
        else:
            rod_color = self.CANVAS_RED if self._any_exhausted(rod_lines) else self.CANVAS_TEXT
        if rod_lines:
            canvas.create_text(
                self.PAD_X, self.PAD_Y,
                text="\n".join(rod_lines),
                anchor="nw",
                font=(Overlay.font_family(), self.FONT_SIZE, "bold"),
                fill=rod_color,
                width=width - self.PAD_X * 2,
                justify="left",
                tags=("rod", "body"),
            )
        if dim_lines:
            # 第二块从第一块的实测底部起算：折过行的长竿行按行数估算会偏小，
            # 两块文字会叠在一起。
            if rod_lines:
                estimated = self.PAD_Y + len(rod_lines) * self._row_height() - 3
                dim_y = self._text_bottom(canvas, "rod", estimated) + 3
            else:
                dim_y = self.PAD_Y
            canvas.create_text(
                self.PAD_X, dim_y,
                text="\n".join(dim_lines),
                anchor="nw",
                font=(Overlay.font_family(), self.FONT_SIZE),
                fill=self.CANVAS_GRAY if not self._capture_active else self.CANVAS_DIM,
                width=width - self.PAD_X * 2,
                justify="left",
                tags=("body",),
            )

    def _content_height(self, lines, width=None):
        """按换行数估算需求高度：长消息按实际换行行数计算，避免被裁切。"""
        try:
            import tkinter.font as tkfont

            wrap_px = (width or WINDOW_WIDTH) - self.PAD_X * 2
            f = tkfont.Font(self.root, family=Overlay.font_family(), size=self.FONT_SIZE, weight="bold")
            row_h = f.metrics("linespace") + 3
            total = 0
            for line in lines:
                visual = max(1, math.ceil(f.measure(line) / max(wrap_px, 1)))
                total += visual * row_h
            # 顶部 + 底部 padding(padx/pady) + 边框余量
            return max(38, total + self.PAD_Y * 2)
        except Exception:
            return 38 + 20 * len(lines)

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

    _WAITING_ROW_RE = re.compile(r"^(\d+号杆|手持竿) (已抛竿|准备抛竿)")

    @classmethod
    def _is_waiting_row(cls, text: str) -> bool:
        return bool(cls._WAITING_ROW_RE.match(text or ""))

    def _reset_to_idle(self, preserve_waiting: bool = True):
        # 会话重置（重连/切服/重启监控）只清理过期状态：已抛竿/准备抛竿的竿行
        # 保留，否则空闲竿会从浮窗消失直到下次抛竿或事件（用户会遇到"竿不见了"）。
        # 会话结束（小退/断连）时 preserve_waiting=False，连等待行一起清空。
        waiting = (
            {
                key: text
                for key, text in self._rows.items()
                if self._is_waiting_row(text)
            }
            if preserve_waiting
            else {}
        )
        self._rows.clear()
        self._rows.update(waiting)
        self._row_restore_map().clear()
        self._telemetry_rows.clear()
        self._rows_dirty = True
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

    def _poll(self):
        delay = self.POLL_INTERVAL_MS
        try:
            self._drain_events()
        except (OSError, sqlite3.Error):
            self._close_sqlite()
            # 读不到就退避重连：每条事件都重连一次的话，建表/WAL 切换的开销全压在
            # Tk 主线程上，浮窗看起来就是"卡一下才跳一批"。
            self._poll_error_streak += 1
            delay = min(
                self.POLL_BACKOFF_MAX_MS,
                self.POLL_INTERVAL_MS * (2 ** self._poll_error_streak),
            )
        else:
            self._poll_error_streak = 0
        finally:
            self._flush_deferred_refresh()
            self._sync_suspend_status()
            self.root.after(delay, self._poll)

    def _drain_events(self) -> None:
        """分批抽干积压事件（最多 POLL_MAX_BATCHES 批），不再按 30ms 一条线地啃。"""
        for _ in range(self.POLL_MAX_BATCHES):
            con = self._sqlite_connection()
            rows = con.execute(
                "SELECT id, payload FROM overlay_events WHERE id > ? ORDER BY id LIMIT ?",
                (self._last_seen_id, self.POLL_BATCH_LIMIT),
            ).fetchall()
            if not rows:
                self._release_stale_connection()
                return
            self._defer_refresh = True
            try:
                for row_id, payload in rows:
                    try:
                        self._handle_event_payload(payload)
                    except Exception:
                        pass
            finally:
                self._defer_refresh = False
            # 游标推进到本批最新事件的自增 id（id 全局单调，不受 bridge 重启影响）。
            self._last_seen_id = rows[-1][0]
            self._on_capture_alive()
            self._flush_deferred_refresh()

    def _flush_deferred_refresh(self):
        if not (self._refresh_pending or self._rows_dirty):
            return
        self._refresh_pending = False
        self._refresh_display()

    def _release_stale_connection(self) -> None:
        """空闲够久就丢一次长连接：事件库被监控侧重建后，旧句柄再也读不到新事件。"""
        if time.time() - self._sqlite_opened_ts < self.POLL_IDLE_REOPEN_SECONDS:
            return
        self._close_sqlite()

    def _sqlite_connection(self):
        con = getattr(self, "_sqlite_con", None)
        if con is not None:
            return con
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
            con.execute("PRAGMA journal_mode = WAL")
            con.commit()
            self._sqlite_con = con
            self._sqlite_opened_ts = time.time()
            self._realign_cursor(con)
        except Exception:
            try:
                con.close()
            except sqlite3.Error:
                pass
            raise
        return con

    def _realign_cursor(self, con) -> None:
        """库被重建后自增 id 从 1 重新开始；游标若还停在旧库的高位就永远读不到新事件。"""
        try:
            row = con.execute("SELECT MAX(id) FROM overlay_events").fetchone()
        except sqlite3.Error:
            return
        if int(row[0] or 0) < self._last_seen_id:
            self._last_seen_id = 0

    def _close_sqlite(self):
        con, self._sqlite_con = getattr(self, "_sqlite_con", None), None
        if con is not None:
            try:
                con.close()
            except sqlite3.Error:
                pass

    def _ensure_sqlite_db(self):
        try:
            self._sqlite_connection()
        except (OSError, sqlite3.Error):
            self._close_sqlite()

    def _latest_event_id(self) -> int:
        try:
            con = self._sqlite_connection()
            row = con.execute("SELECT MAX(id) FROM overlay_events").fetchone()
            return int(row[0] or 0)
        except (OSError, sqlite3.Error):
            self._close_sqlite()
            return 0

    def _suspend_status_line(self) -> str:
        """挂起状态行文本；测量高度、绘制、轮询比对三处必须一致。"""
        if self._suspend_loop is None:
            return ""
        return self._suspend_error or self._suspend_loop.status_text()

    def _start_suspend_hotkey(self):
        if self._suspend_loop is None:
            return
        wanted = self._suspend_config.hotkey
        self._hotkey = GlobalHotkey(wanted)
        if not self._hotkey.start():
            self._hotkey = None
            self._suspend_error = f"{wanted} 等热键都被占用，挂起不可用"
            self._refresh_display()
            return
        self._suspend_error = None
        # 状态文本要报真正绑上的键：首选键被占用时会自动顺延。
        self._suspend_loop.hotkey_label = self._hotkey.bound_key or wanted

    def _start_suspend_engine(self):
        """把挂起控制器放到独立线程：节拍只由 SUSPEND_TICK_INTERVAL_MS 决定。

        线程只做 Win32 挂起/恢复、轮询热键和执行事件线程投递的来鱼动作，
        绝不碰 Tk；浮窗在 _poll 里读 status_text() 决定是否重绘。
        """
        if self._suspend_loop is None:
            return
        self._suspend_stop = threading.Event()
        self._suspend_thread = threading.Thread(
            target=self._suspend_worker, name="rf4-suspend", daemon=True
        )
        self._suspend_thread.start()

    def _suspend_worker(self):
        loop = self._suspend_loop
        hotkey = self._hotkey
        stop = self._suspend_stop
        interval = self.SUSPEND_TICK_INTERVAL_MS / 1000.0
        while stop is not None and not stop.wait(interval):
            try:
                if hotkey is not None and hotkey.poll():
                    loop.toggle()
                loop.tick()
            except Exception:
                # 一次 Win32 调用出错不能停摆，否则游戏就永久冻在这里了。
                continue

    def _sync_suspend_status(self):
        """把线程里的挂起状态搬到浮窗上：文本变了才重绘一次。"""
        if self._suspend_loop is None:
            return
        status = self._suspend_status_line()
        if status != self._last_suspend_status:
            self._last_suspend_status = status
            self._refresh_display()

    def _update_suspend_on_fish(self, name, gear_slot):
        """来鱼解冻、咬钩冻回：动作只投递给挂起线程，Tk 线程不碰 Win32。

        鱼被冻在咬钩那一帧，玩家有不限时看浮窗，要拉杆再按热键恢复进程。
        """
        step = self.SUSPEND_FISH_FLOW.get(name)
        loop = self._suspend_loop
        if step is None or loop is None:
            return
        action, verb = step
        loop.request(action, f"{gear_slot}{verb}" if verb else "")

    def _close_suspend(self):
        thread = self._suspend_thread
        stop = self._suspend_stop
        self._suspend_thread = None
        self._suspend_stop = None
        if stop is not None:
            stop.set()
        if thread is not None:
            thread.join(timeout=self.SUSPEND_THREAD_JOIN_TIMEOUT_SECONDS)
        if self._hotkey is not None:
            self._hotkey.stop()
            self._hotkey = None
        if self._suspend_loop is not None:
            # 退出只解除接管，不替他恢复目标进程：需要手动恢复时先按热键再退出。
            self._suspend_loop.detach()
            self._suspend_loop = None

    def _on_capture_alive(self):
        if not self._capture_active:
            self._capture_active = True
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
        self._update_suspend_on_fish(name, gear_slot)
        # 来鱼/咬钩保持到下一条事件(咬钩/搏鱼/结算/脱钩)覆盖，不再定时消失；
        # 入护/脱钩/放生维持 3 秒后消失。
        if name in ("fish_kept", "fish_escaped", "fish_released"):
            clear_after = 3000
        else:
            clear_after = 0
        if name == "reset":
            # 会话开始（含切服承接）：保留已抛竿的竿行，由引擎补发确认。
            self._reset_to_idle(preserve_waiting=True)
        elif name == "session_end":
            # 会话结束（小退/断连）：连等待中的竿行一起清空。
            self._reset_to_idle(preserve_waiting=False)
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
