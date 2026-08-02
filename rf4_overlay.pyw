"""RF4 来鱼浮窗提醒

监听 RF4 Monitor 的 UDP 事件桥，来鱼时在屏幕角落弹出透明置顶浮窗，
入护后消失。可按住鼠标拖动到任意位置，位置会自动记忆。
"""
import json
import math
import socket
import sys
import threading
import tkinter as tk
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    # 打包态：__file__ 指向临时解压区(_MEIPASS)，改用 exe 所在目录，
    # 才能正确读写随 exe 分发的 rf4_overlay_config.json 与鱼种标签。
    BASE_DIR = Path(sys.executable).resolve().parent
CONFIG_FILE = BASE_DIR / "rf4_overlay_config.json"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 25000
WINDOW_WIDTH = 320
WINDOW_HEIGHT = 70


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
    path = BASE_DIR / "fish_labels_zh.json"
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
    # 样式参数：背景色 / 前景色 / 透明键色
    # 透明模式：用背景色作为透明键，仅文字可见。
    # 深色模式：透明键设为一个绝不出现的哨兵色，背景即恢复不透明。
    _STYLE_PARAMS = {
        STYLE_DARK: {"bg": "#101418", "fg": "#ffd166", "key": "#0000FF"},
        STYLE_TRANSPARENT: {"bg": "#101418", "fg": "#ffd166", "key": "#101418"},
    }

    def __init__(self, root, host, port):
        self.root = root
        self.host = host
        self.port = port
        self.labels = load_fish_labels()
        self.visible = False
        self._drag_offset = None
        # 按竿号分行显示：key=竿号文本, value=该竿最新状态行
        self._rows = {}
        # 遥测信息区：多条(商店/装备等)，有序，最多保留 MAX_TELEMETRY_ROWS 条
        self._telemetry_rows = {}
        self._telemetry_seq = 0
        self._idle_visible = False

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

        self.label = tk.Label(
            root,
            text="",
            bg=self._STYLE_PARAMS[self.style]["bg"],
            fg=self._STYLE_PARAMS[self.style]["fg"],
            font=("Microsoft YaHei UI", 13, "bold"),
            padx=16,
            pady=12,
            wraplength=WINDOW_WIDTH - 32,
            justify="left",
            anchor="w",
        )
        self.label.pack(fill="both", expand=True)
        # 统一应用背景样式(含透明键设置)
        self.apply_style(self.style)

        self._apply_noactivate()
        self._bind_drag(self.root)
        self._bind_drag(self.label)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
        except OSError as exc:
            self.root.destroy()
            from tkinter import messagebox

            try:
                root2 = tk.Tk()
                root2.withdraw()
                messagebox.showerror(
                    "RF4 来鱼提醒 - 启动失败",
                    f"无法监听 UDP {self.host}:{self.port}。\n\n"
                    f"可能原因：已有 RF4 来鱼提醒实例在运行，或端口被占用。\n"
                    f"错误：{exc}\n\n"
                    f"请先关闭已运行的浮窗/监控，再重新双击启动。",
                    parent=root2,
                )
                root2.destroy()
            except Exception:
                pass
            return

        self.sock.settimeout(0.2)
        self._refresh_display()
        self.root.after(100, self._poll)
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
        bg = params["bg"]
        fg = params["fg"]
        key = params["key"]
        self.style = style
        self.root.configure(bg=bg)
        self.label.configure(bg=bg, fg=fg)
        try:
            # Windows 透明键：设置对应颜色键。深色模式用哨兵色(窗口不使用)令背景恢复不透明。
            self.root.wm_attributes("-transparentcolor", key)
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
        # 简单分行：所有行(鱼事件按竿号 + 遥测/频道/聊天)按序拼接；无内容回待机。
        lines = list(self._rows.values())
        for seq, text in self._telemetry_rows.items():
            lines.append(text)
        if not lines:
            lines = ["RF4 来鱼提醒 · 待机中"]
        display = "\n".join(lines)
        self.label.config(text=display)
        # 按内容实际需求高度调整窗口，避免多杆/换行时内容被裁切
        need_h = self._content_height(lines)
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        self.root.geometry(f"{WINDOW_WIDTH}x{need_h}+{x}+{y}")
        self._show()

    def _content_height(self, lines):
        """按换行数估算需求高度：长消息按实际换行行数计算，避免被裁切。"""
        try:
            import tkinter.font as tkfont

            wrap_px = WINDOW_WIDTH - 32
            f = tkfont.Font(self.root, font=self.label.cget("font"))
            row_h = f.metrics("linespace") + 4
            total = 0
            for line in lines:
                visual = max(1, math.ceil(f.measure(line) / max(wrap_px, 1)))
                total += visual * row_h
            # 顶部 + 底部 padding(padx/pady) + 边框余量
            return max(40, total + 40)
        except Exception:
            return 40 + 28 * len(lines)

    def _show_incoming(self, fish_key, fish_name, weight_g, gear_slot=""):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        weight = ""
        if weight_g:
            weight = f"{weight_g}克" if weight_g < 1000 else f"{weight_g / 1000:.3f}公斤"
        prefix = f"[{gear_slot}] " if gear_slot else ""
        self._update_row(gear_slot, f"【我自己】：{prefix}有{name} {weight} 过来了")

    def _show_bitten(self, fish_key, fish_name, weight_g, gear_slot=""):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        weight = ""
        if weight_g:
            weight = f"{weight_g}克" if weight_g < 1000 else f"{weight_g / 1000:.3f}公斤"
        prefix = f"[{gear_slot}] " if gear_slot else ""
        weight_text = f" {weight}" if weight else ""
        self._update_row(gear_slot, f"【我自己】：{prefix}{name}{weight_text} 咬钩了")

    def _show_kept(self, fish_key, fish_name, weight_g, gear_slot=""):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        weight = ""
        if weight_g:
            weight = f"{weight_g}克" if weight_g < 1000 else f"{weight_g / 1000:.3f}公斤"
        prefix = f"[{gear_slot}] " if gear_slot else ""
        self._update_row(gear_slot, f"【我自己】：{prefix}有{name} {weight} 入护了", clear_after=3000)

    def _show_escaped(self, fish_key, fish_name, weight_g, gear_slot=""):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        weight = ""
        if weight_g:
            weight = f"{weight_g}克" if weight_g < 1000 else f"{weight_g / 1000:.3f}公斤"
        prefix = f"[{gear_slot}] " if gear_slot else ""
        weight_text = f" {weight}" if weight else ""
        self._update_row(gear_slot, f"【我自己】：{prefix}{name}{weight_text} 挣脱跑了（脱钩）", clear_after=3000)

    def _show_released(self, fish_key, fish_name, weight_g, gear_slot=""):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        prefix = f"[{gear_slot}] " if gear_slot else ""
        self._update_row(gear_slot, f"【我自己】：{prefix}放生了 {name}", clear_after=3000)

    def _show_generic(self, text):
        # 频道鱼获/公共聊天/遥测等"信息类"统一进遥测区，独立分行显示。
        self._show_telemetry(text)

    def _show_anticheat(self, text):
        self.label.config(fg="#ff5252")
        self._show_telemetry(text)
        self.root.after(8000, lambda: self.label.config(fg="#ffd166"))

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

    def _poll(self):
        try:
            while True:
                try:
                    data, _ = self.sock.recvfrom(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                try:
                    event = json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    continue
                name = event.get("event")
                gear_slot = event.get("gear_slot") or ""
                if name == "fish_incoming":
                    self.root.after(0, self._show_incoming, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"), gear_slot)
                elif name == "fish_bitten":
                    self.root.after(0, self._show_bitten, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"), gear_slot)
                elif name == "fish_kept":
                    self.root.after(0, self._show_kept, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"), gear_slot)
                elif name == "fish_escaped":
                    self.root.after(0, self._show_escaped, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"), gear_slot)
                elif name == "fish_released":
                    self.root.after(0, self._show_released, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"), gear_slot)
                elif name in ("fish_catch", "chat"):
                    self.root.after(0, self._show_generic, event.get("text") or "")
                elif name == "telemetry":
                    text = event.get("text") or ""
                    if text:
                        self.root.after(0, self._show_generic, text)
                elif name == "anticheat":
                    self.root.after(0, self._show_anticheat, event.get("text") or "")
        finally:
            self.root.after(100, self._poll)


def main():
    config = load_config()
    host = config.get("host", DEFAULT_HOST)
    port = config.get("port", DEFAULT_PORT)
    root = tk.Tk()
    root.title("RF4 来鱼提醒")
    Overlay(root, host, port)
    root.mainloop()


if __name__ == "__main__":
    main()
