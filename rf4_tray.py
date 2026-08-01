"""RF4 Monitor 系统托盘控制程序。

在系统托盘提供一个图标，通过右键菜单一键启动/停止 RF4 Monitor 监控
（主程序 launcher + mitmdump + 来鱼浮窗），无需手动执行多个脚本。

用法：
    pythonw rf4_tray.py

依赖：
    pip install pystray pillow
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
MONITOR_LOG = LOG_DIR / "rf4_monitor.log"
EVENT_BRIDGE_PORT = 25000

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception as exc:
    sys.exit(f"[rf4-tray] 缺少依赖 pystray/Pillow，请运行: pip install pystray pillow\n{exc}")

_state = {
    "launcher_proc": None,
    "overlay_proc": None,
    "running": False,
}


def _find_children(parent_pid: int) -> list[int]:
    pids: list[int] = []
    try:
        out = subprocess.check_output(
            [
                "wmic",
                "process",
                "where",
                f"(ParentProcessId={parent_pid})",
                "get",
                "ProcessId",
            ],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
        )
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit() and int(line) != parent_pid:
                pids.append(int(line))
    except Exception:
        pass
    return pids


def _terminate_pid_tree(pid: int) -> None:
    children = _find_children(pid)
    for child in children:
        _terminate_pid_tree(child)
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass


def _pythonw() -> str:
    candidates = [
        BASE_DIR / ".venv" / "Scripts" / "pythonw.exe",
        BASE_DIR / ".venv" / "Scripts" / "python.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return "pythonw.exe"


def _is_alive(proc) -> bool:
    if proc is None:
        return False
    return proc.poll() is None


def start_monitor() -> str:
    if _state["running"]:
        return "已在运行"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    pythonw = _pythonw()
    launcher = subprocess.Popen(
        [
            pythonw,
            str(BASE_DIR / "rf4_monitor.py"),
            "--set",
            f"rf4_event_bridge_port={EVENT_BRIDGE_PORT}",
        ],
        cwd=str(BASE_DIR),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if pythonw.endswith("python.exe") else 0,
    )
    time.sleep(1.5)
    overlay = subprocess.Popen(
        [pythonw, str(BASE_DIR / "rf4_overlay.pyw")],
        cwd=str(BASE_DIR),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if pythonw.endswith("python.exe") else 0,
    )
    _state["launcher_proc"] = launcher
    _state["overlay_proc"] = overlay
    _state["running"] = True
    return "已启动"


def stop_monitor() -> str:
    if not _state["running"]:
        return "未在运行"
    launcher = _state["launcher_proc"]
    overlay = _state["overlay_proc"]
    if launcher is not None and _is_alive(launcher):
        # 先终止 launcher 进程树（含 mitmdump），launcher 退出时会自动恢复 hosts
        _terminate_pid_tree(launcher.pid)
    if overlay is not None and _is_alive(overlay):
        _terminate_pid_tree(overlay.pid)
    _state["launcher_proc"] = None
    _state["overlay_proc"] = None
    _state["running"] = False
    return "已停止"


def _open_log() -> None:
    if not MONITOR_LOG.exists():
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        MONITOR_LOG.write_text("", encoding="utf-8")
    os.startfile(str(MONITOR_LOG))


def _status_text() -> str:
    return "运行中" if _state["running"] else "已停止"


def _make_icon() -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((8, 8, 56, 56), fill=(22, 118, 210, 255))
    draw.polygon([(18, 34), (30, 22), (40, 28), (48, 20), (52, 34)], fill=(255, 209, 102, 255))
    return img


def on_start(icon, item):
    msg = start_monitor()
    icon.notify(msg, "RF4 Monitor")


def on_stop(icon, item):
    msg = stop_monitor()
    icon.notify(msg, "RF4 Monitor")


def on_quit(icon, item):
    if _state["running"]:
        stop_monitor()
    icon.stop()


def on_log(icon, item):
    _open_log()


def main() -> None:
    icon = pystray.Icon(
        "rf4_monitor_tray",
        icon=_make_icon(),
        title="RF4 Monitor",
        menu=pystray.Menu(
            pystray.MenuItem("启动监控", on_start),
            pystray.MenuItem("停止监控", on_stop),
            pystray.MenuItem("查看日志", on_log),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", on_quit),
        ),
    )
    icon.run()


if __name__ == "__main__":
    main()
