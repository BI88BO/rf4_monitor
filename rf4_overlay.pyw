"""RF4 来鱼浮窗提醒

监听 RF4 Monitor 的 UDP 事件桥，来鱼时在屏幕角落弹出透明置顶浮窗，
入护后消失。可按住鼠标拖动到任意位置，位置会自动记忆。
"""
import json
import socket
import threading
import tkinter as tk
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
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
    # 样式参数：背景色 / 前景色 / 是否透明键
    _STYLE_PARAMS = {
        STYLE_DARK: {"bg": "#101418", "fg": "#ffd166", "transparent": False},
        STYLE_TRANSPARENT: {"bg": "#101418", "fg": "#ffd166", "transparent": True},
    }

    def __init__(self, root, host, port):
        self.root = root
        self.host = host
        self.port = port
        self.labels = load_fish_labels()
        self.visible = False
        self._drag_offset = None
        # 按杆号分行显示：key=杆号文本, value=该杆最新状态行
        self._rows = {}
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
            justify="center",
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
        transparent = params["transparent"]
        self.style = style
        self.root.configure(bg=bg)
        self.label.configure(bg=bg, fg=fg)
        try:
            if transparent:
                self.root.wm_attributes("-transparentcolor", bg)
            else:
                # 传入空串关闭透明键，恢复为不透明深色气泡背景
                self.root.wm_attributes("-transparentcolor", "")
                self.label.configure(fg=fg)
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

    def _refresh_display(self):
        lines = list(self._rows.values())
        if not lines:
            lines = ["RF4 来鱼提醒 · 待机中"]
        display = "\n".join(lines)
        self.label.config(text=display)
        # 按行数调整窗口高度
        row_h = 26
        h = 40 + row_h * len(lines)
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        self.root.geometry(f"{WINDOW_WIDTH}x{h}+{x}+{y}")
        self._show()

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
        self._update_row("", text, clear_after=3000)

    def _show_anticheat(self, text):
        self.label.config(fg="#ff5252")
        self._update_row("", text, clear_after=8000)
        self.root.after(8000, lambda: self.label.config(fg="#ffd166"))

    def _reset_to_idle(self):
        self._rows.clear()
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
