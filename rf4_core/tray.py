"""RF4 Monitor 系统托盘控制程序。

在系统托盘提供一个图标，通过右键菜单一键启动/停止 RF4 Monitor 监控
（主程序 launcher + mitmdump + 来鱼浮窗），无需手动执行多个脚本。

用法：
    pythonw deskmon_tray.py

依赖：
    pip install pystray pillow
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import socket
import sys
import time
from subprocess import TimeoutExpired
from pathlib import Path

# 单实例互斥量名称：防止重复启动多个托盘导致多进程抢端口/多浮窗。
# 用 Local 会话作用域（Global 需 SeCreateGlobalPrivilege，非提权下会 ACCESS_DENIED）。
_SINGLE_INSTANCE_MUTEX = "Local\\DeskMonTray"
ERROR_ALREADY_EXISTS = 183


def _acquire_single_instance() -> None:
    """获取全局互斥量；若另一个托盘实例已存在则直接退出。

    互斥量由本进程持有时释放，进程结束自动释放，不会像锁文件那样残留。
    """
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, _SINGLE_INSTANCE_MUTEX)
    if not handle or kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        sys.exit("[rf4-tray] 已有托盘实例在运行，本次启动已自动退出。")
    # 保持句柄引用，避免被 GC 提前释放导致互斥量失效。
    globals()["_single_instance_handle"] = handle

PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = PACKAGE_DIR.parent
if getattr(sys, "frozen", False):
    # 打包态：脚本路径指向临时解压区(_MEIPASS)，改用 exe 所在目录，
    # 才能找到随 exe 分发的 DeskMon.exe 与数据文件。
    BASE_DIR = Path(sys.executable).resolve().parent
LOG_DIR = BASE_DIR / "logs"
MONITOR_LOG = LOG_DIR / "rf4_monitor.log"
SNIFFER_LOG = LOG_DIR / "rf4_sniffer.log"
SHOW_CONFIG_FILE = PACKAGE_DIR / "rf4_show_config.json"
MODE_CONFIG_FILE = PACKAGE_DIR / "rf4_mode.json"

MODE_PROXY = "proxy"
MODE_PASSIVE = "passive"


def _load_mode() -> str:
    try:
        data = json.loads(MODE_CONFIG_FILE.read_text("utf-8"))
        if data.get("mode") == MODE_PASSIVE:
            return MODE_PASSIVE
    except (OSError, ValueError):
        pass
    return MODE_PROXY


def _save_mode(mode: str) -> None:
    try:
        MODE_CONFIG_FILE.write_text(
            json.dumps({"mode": mode}, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass


def _toggle_mode(icon, item) -> None:
    mode = MODE_PASSIVE if _load_mode() == MODE_PROXY else MODE_PROXY
    _save_mode(mode)
    if _state.get("running"):
        icon.notify("切换模式需要先停止监控再重新启动。", "来鱼提示")
    else:
        label = "被动抓包" if mode == MODE_PASSIVE else "代理"
        icon.notify(f"已切换为{label}模式", "来鱼提示")


def _checked_mode(item) -> bool:
    return _load_mode() == MODE_PASSIVE

# 浮窗背景样式配置(与 overlay.pyw 约定一致)
OVERLAY_CONFIG_FILE = PACKAGE_DIR / "rf4_overlay_config.json"
OVERLAY_STYLE_DARK = "dark"
OVERLAY_STYLE_TRANSPARENT = "transparent"
OVERLAY_STYLES = (OVERLAY_STYLE_DARK, OVERLAY_STYLE_TRANSPARENT)

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
    ("telemetry_fish", "遥测·钓鱼过程", "rf4_show_fish"),
    ("fight_status", "搏鱼状态行", "rf4_show_fight_status"),
    ("fight_details", "遥测·搏鱼过程(位置/拉线)", "rf4_show_fight_details"),
    ("telemetry_player", "遥测·玩家坐标/状态", "rf4_show_player"),
    ("telemetry_feed", "遥测·打窝/投喂", "rf4_show_feed"),
    ("telemetry_chat", "遥测·公共聊天", "rf4_show_chat"),
    ("telemetry_room", "遥测·房间消息", "rf4_show_room"),
    ("telemetry_session", "遥测·会话信息", "rf4_show_session"),
    ("telemetry_item", "遥测·装备/物品", "rf4_show_item"),
    ("telemetry_building", "遥测·商店/鱼市/工坊/船", "rf4_show_building"),
    ("telemetry_unknown", "遥测·未知协议", "rf4_show_unknown"),
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


def _load_overlay_config() -> dict:
    try:
        if OVERLAY_CONFIG_FILE.exists():
            data = json.loads(OVERLAY_CONFIG_FILE.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        pass
    return {}


def _save_overlay_config(data: dict) -> None:
    merged = _load_overlay_config()
    merged.update(data)
    try:
        OVERLAY_CONFIG_FILE.write_text(
            json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass


def _get_overlay_style() -> str:
    cfg = _load_overlay_config()
    style = cfg.get("style")
    if style in OVERLAY_STYLES:
        return style
    return OVERLAY_STYLE_DARK


STYLE_LABELS = {
    OVERLAY_STYLE_DARK: "深色气泡",
    OVERLAY_STYLE_TRANSPARENT: "透明悬浮",
}


def _style_label_to_value(label: str) -> str:
    for style, lab in STYLE_LABELS.items():
        if lab == label:
            return style
    return ""


def _set_overlay_style(icon, item) -> None:
    style = _style_label_to_value(str(item.text))
    if not style:
        return
    _save_overlay_config({"style": style})
    if _state.get("running"):
        icon.notify(
            f"浮窗样式已切换为 {STYLE_LABELS[style]}", "来鱼提示"
        )


def _checked_style(item) -> bool:
    return str(item.text) == STYLE_LABELS[_get_overlay_style()]

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
    "web_monitor_proc": None,
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


def _terminate_pid_tree(pid: int, *, force: bool = True) -> None:
    children = _find_children(pid)
    for child in children:
        _terminate_pid_tree(child, force=force)
    try:
        command = ["taskkill", "/PID", str(pid), "/T"]
        if force:
            command.append("/F")
        subprocess.run(
            command,
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
    mode = _load_mode()
    mode_args = ["--mode", mode] if mode == MODE_PASSIVE else []

    if frozen:
        # 打包态：单个 exe 通过 --role 拉起引擎与浮窗，无需分发的独立子 exe。
        self_exe = str(Path(sys.executable).resolve())
        launcher_cmd = [
            self_exe,
            "--role",
            "engine",
            *mode_args,
            "--set",
            f"rf4_show_config_path={SHOW_CONFIG_FILE}",
        ]
        overlay_cmd = [self_exe, "--role", "overlay"]
        creationflags = 0
    else:
        pythonw = _pythonw()
        launcher_cmd = [
            pythonw,
            str(BASE_DIR / "rf4_core" / "engine.py"),
            *mode_args,
            "--set",
            f"rf4_show_config_path={SHOW_CONFIG_FILE}",
        ]
        overlay_cmd = [pythonw, str(BASE_DIR / "rf4_core" / "overlay.pyw")]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if pythonw.endswith("python.exe") else 0

    # 把可勾选的显示项转成 --set 参数传给 addon
    for key, _, option in SHOW_ITEMS:
        launcher_cmd.extend(["--set", f"{option}={str(show_config.get(key, True)).lower()}"])
    # 把托盘自身 PID 传给子进程，供其守护线程在托盘退出时自动清理进程链。
    child_env = dict(os.environ)
    child_env["DESKMON_PARENT_PID"] = str(os.getpid())
    launcher = subprocess.Popen(
        launcher_cmd,
        cwd=str(BASE_DIR),
        creationflags=creationflags,
        env=child_env,
    )
    time.sleep(1.5)
    overlay = subprocess.Popen(
        overlay_cmd,
        cwd=str(BASE_DIR),
        creationflags=creationflags,
        env=child_env,
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
        # 浮窗退出前需要释放全局热键；先正常退出，强杀只是兜底。
        _terminate_pid_tree(overlay.pid, force=False)
        try:
            overlay.wait(timeout=2)
        except TimeoutExpired:
            pass
        if _is_alive(overlay):
            _terminate_pid_tree(overlay.pid)
    _state["launcher_proc"] = None
    _state["overlay_proc"] = None
    _state["running"] = False
    return "已停止"


def _toggle_web_monitor(icon, item) -> None:
    proc = _state["web_monitor_proc"]
    if proc is not None and _is_alive(proc):
        _terminate_pid_tree(proc.pid)
        _state["web_monitor_proc"] = None
        icon.notify("手机网页监控已停止", "来鱼提示")
    else:
        python_exe = sys.executable
        script = str(BASE_DIR / "rf4_core" / "web_monitor.py")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        p = subprocess.Popen(
            [python_exe, script],
            creationflags=creationflags,
        )
        _state["web_monitor_proc"] = p
        ip = _get_local_ip()
        icon.notify(f"手机访问 http://{ip}:8088", "手机网页监控已启动")


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _checked_web_monitor(item) -> bool:
    proc = _state["web_monitor_proc"]
    return proc is not None and _is_alive(proc)


def _open_log() -> None:
    log_file = SNIFFER_LOG if _load_mode() == MODE_PASSIVE else MONITOR_LOG
    if not log_file.exists():
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")
    os.startfile(str(log_file))


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
    icon.notify(msg, "来鱼提示")


def on_stop(icon, item):
    msg = stop_monitor()
    icon.notify(msg, "来鱼提示")


def on_quit(icon, item):
    if _state["running"]:
        stop_monitor()
    icon.stop()


def on_log(icon, item):
    _open_log()


def main() -> None:
    _acquire_single_instance()

    show_menu_items = [
        pystray.MenuItem(label, _toggle_show, checked=_checked_show) for _, label, _ in SHOW_ITEMS
    ]
    style_menu_items = [
        pystray.MenuItem(
            STYLE_LABELS[style], _set_overlay_style, checked=_checked_style
        )
        for style in OVERLAY_STYLES
    ]
    icon = pystray.Icon(
        "deskmon_tray",
        icon=_make_icon(),
        title="来鱼提示",
        menu=pystray.Menu(
            pystray.MenuItem("启动监控", on_start),
            pystray.MenuItem("停止监控", on_stop),
            pystray.MenuItem("查看日志", on_log),
            pystray.MenuItem("模式：被动抓包", _toggle_mode, checked=_checked_mode),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("显示设置", pystray.Menu(*show_menu_items)),
            pystray.MenuItem("浮窗样式", pystray.Menu(*style_menu_items)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("手机网页监控", _toggle_web_monitor, checked=_checked_web_monitor),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", on_quit),
        ),
    )
    icon.run()


if __name__ == "__main__":
    main()
