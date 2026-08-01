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
    try:
        CONFIG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
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
    def __init__(self, root, host, port):
        self.root = root
        self.host = host
        self.port = port
        self.labels = load_fish_labels()
        self.visible = False
        self._drag_offset = None

        config = load_config()
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
        self.root.configure(bg="#101418")

        self.label = tk.Label(
            root,
            text="",
            bg="#101418",
            fg="#ffd166",
            font=("Microsoft YaHei UI", 13, "bold"),
            padx=16,
            pady=12,
            wraplength=WINDOW_WIDTH - 32,
            justify="center",
        )
        self.label.pack(fill="both", expand=True)

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
        self.label.config(text="RF4 来鱼提醒 · 待机中")
        self._show()
        self.root.after(100, self._poll)

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

    def _show_incoming(self, fish_key, fish_name, weight_g):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        weight = ""
        if weight_g:
            weight = f"{weight_g}克" if weight_g < 1000 else f"{weight_g / 1000:.3f}公斤"
        self.label.config(text=f"【我自己】： 有{name} {weight} 过来了")
        self._show()

    def _show_kept(self, fish_key, fish_name, weight_g):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        weight = ""
        if weight_g:
            weight = f"{weight_g}克" if weight_g < 1000 else f"{weight_g / 1000:.3f}公斤"
        self.label.config(text=f"【我自己】： 有{name} {weight} 入护了")
        self._show()

    def _show_escaped(self, fish_key, fish_name, weight_g):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        self.label.config(text=f"【我自己】： {name} 挣脱跑了（脱钩）")
        self._show()

    def _show_released(self, fish_key, fish_name, weight_g):
        name = self.labels.get(fish_key) or fish_name or fish_key or "未知鱼类"
        self.label.config(text=f"【我自己】： 放生了 {name}")
        self._show()

    def _reset_to_idle(self):
        self.label.config(text="RF4 来鱼提醒 · 待机中")
        self._show()

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
                if name == "fish_incoming":
                    self.root.after(0, self._show_incoming, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"))
                elif name == "fish_kept":
                    self.root.after(0, self._show_kept, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"))
                elif name == "fish_escaped":
                    self.root.after(0, self._show_escaped, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"))
                elif name == "fish_released":
                    self.root.after(0, self._show_released, event.get("fish_key"), event.get("fish_name"), event.get("weight_g"))
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
