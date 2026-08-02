"""RF4 Monitor 系统托盘控制程序。

在系统托盘提供一个图标，通过右键菜单一键启动/停止 RF4 Monitor 监控
（主程序 launcher + mitmdump + 来鱼浮窗），无需手动执行多个脚本。

用法：
    pythonw rf4_tray.py

依赖：
    pip install pystray pillow
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    # 打包态：脚本路径指向临时解压区(_MEIPASS)，改用 exe 所在目录，
    # 才能找到随 exe 分发的 RF4Monitor.exe / RF4Overlay.exe 与数据文件。
    BASE_DIR = Path(sys.executable).resolve().parent
LOG_DIR = BASE_DIR / "logs"
MONITOR_LOG = LOG_DIR / "rf4_monitor.log"
EVENT_BRIDGE_PORT = 25000
SHOW_CONFIG_FILE = BASE_DIR / "rf4_show_config.json"

# 可勾选的显示项：(配置键, 菜单文本, addon 选项名)
# 这些控制浮窗显示；日志始终全量输出，不受显示设置影响。
SHOW_ITEMS = [
    ("incoming", "自己来鱼", "rf4_show_incoming"),
    ("bitten", "确认咬钩", "rf4_show_bitten"),
    ("kept", "自己入护", "rf4_show_kept"),
    ("escaped", "自己脱钩", "rf4_show_escaped"),
    ("released", "自己放生", "rf4_show_released"),
    ("catch_broadcast", "频道鱼获（其他玩家）", "rf4_show_catch_broadcast"),
    ("chat_broadcast", "公共聊天", "rf4_show_chat_broadcast"),
]

DEFAULT_SHOW = {key: True for key, _, _ in SHOW_ITEMS}


def _load_show_config() -> dict:
    config = dict(DEFAULT_SHOW)
    try:
        if SHOW_CONFIG_FILE.exists():
            data = json.loads(SHOW_CONFIG_FILE.read_text("utf-8"))
            if isinstance(data, dict):
                for key in config:
                    if key in data and isinstance(data[key], bool):
                        config[key] = data[key]
    except (OSError, ValueError):
        pass
    return config


def _save_show_config(config: dict) -> None:
    try:
        SHOW_CONFIG_FILE.write_text(
            json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception as exc:
    sys.exit(f"[rf4-tray] 缺少依赖 pystray/Pillow，请运行: pip install pystray pillow\n{exc}")

_state = {
    "launcher_proc": None,
    "overlay_proc": None,
    "running": False,
    "show_config": None,
}


def _get_show_config() -> dict:
    if _state["show_config"] is None:
        _state["show_config"] = _load_show_config()
    return _state["show_config"]


def _toggle_show(icon, item) -> None:
    config = _get_show_config()
    key = str(item.text)
    # 从菜单文本反查配置键
    for k, label, _ in SHOW_ITEMS:
        if label == key:
            config[k] = not config[k]
            break
    _save_show_config(config)
    # 不调用 icon.update_menu()：它会重建托盘菜单导致已打开的"显示设置"菜单关闭。
    # 勾选状态已保存，下次打开菜单时 checked 回调读取最新配置。

def _checked_show(item) -> bool:
    key = str(item.text)
    config = _get_show_config()
    for k, label, _ in SHOW_ITEMS:
        if label == key:
            return bool(config.get(k, True))
    return True


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
    show_config = _load_show_config()
    frozen = getattr(sys, "frozen", False)

    if frozen:
        # 打包态：直接调用随 exe 分发的 RF4Monitor（launcher 模式）与浮窗 exe。
        launcher_cmd = [
            str(BASE_DIR / "RF4Monitor.exe"),
            "--set",
            f"rf4_event_bridge_port={EVENT_BRIDGE_PORT}",
        ]
        overlay_cmd = [str(BASE_DIR / "RF4Overlay.exe")]
        creationflags = 0
    else:
        pythonw = _pythonw()
        launcher_cmd = [
            pythonw,
            str(BASE_DIR / "rf4_monitor.py"),
            "--set",
            f"rf4_event_bridge_port={EVENT_BRIDGE_PORT}",
        ]
        overlay_cmd = [pythonw, str(BASE_DIR / "rf4_overlay.pyw")]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if pythonw.endswith("python.exe") else 0

    # 把可勾选的显示项转成 --set 参数传给 addon
    for key, _, option in SHOW_ITEMS:
        launcher_cmd.extend(["--set", f"{option}={str(show_config.get(key, True)).lower()}"])
    launcher = subprocess.Popen(
        launcher_cmd,
        cwd=str(BASE_DIR),
        creationflags=creationflags,
    )
    time.sleep(1.5)
    overlay = subprocess.Popen(
        overlay_cmd,
        cwd=str(BASE_DIR),
        creationflags=creationflags,
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
    show_menu_items = [
        pystray.MenuItem(label, _toggle_show, checked=_checked_show) for _, label, _ in SHOW_ITEMS
    ]
    icon = pystray.Icon(
        "rf4_monitor_tray",
        icon=_make_icon(),
        title="RF4 Monitor",
        menu=pystray.Menu(
            pystray.MenuItem("启动监控", on_start),
            pystray.MenuItem("停止监控", on_stop),
            pystray.MenuItem("查看日志", on_log),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("显示设置", pystray.Menu(*show_menu_items)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", on_quit),
        ),
    )
    icon.run()


if __name__ == "__main__":
    main()
