# -*- mode: python ; coding: utf-8 -*-
"""RF4 Monitor 统一打包入口（单 exe 多角色）。

单个 RF4Monitor.exe 通过命令行参数分派运行不同角色，避免打包出
RF4Tray.exe / RF4Monitor.exe / RF4Overlay.exe 三个分散文件：

- 无参数 / ``--role tray``：系统托盘（默认）。用户双击 exe 即进入托盘。
- ``--role engine``：监控引擎。代理模式走 launcher（内部以 RF4_ENGINE_MODE=1
  拉起本 exe 扮演 mitmdump）；被动模式走 sniffer.run_passive。
- ``--role overlay``：来鱼浮窗。

数据文件（fish_labels_zh.json、rf4_show_config.json、reference_defaults.txt 等）
仍放在 exe 所在目录，由 rf4_core.data_root() 定位；配置文件可写。
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin(argv: list[str]) -> bool:
    """以 runas(UAC) 重新启动自身；返回是否成功发起。

    失败(用户取消/拒绝/无法提权)时返回 False，由调用方决定继续或退出。
    """
    try:
        exe = str(Path(sys.executable).resolve())
        cmdline = subprocess.list2cmdline(argv)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, cmdline, str(Path(exe).parent), 0
        )
        return result > 32
    except Exception:
        return False


def _dispatch_tray(argv: list[str]) -> int:
    if not _is_admin():
        if _relaunch_as_admin(argv):
            return 0  # 已交由新的管理员进程处理，本进程退出。
        print("[rf4-all] 需要管理员权限运行 RF4 Monitor（请允许 UAC 提示）。", file=sys.stderr)
        return 2
    import deskmon_tray

    deskmon_tray.main()
    return 0


def _dispatch_overlay() -> int:
    import deskmon_overlay as overlay

    overlay.main()
    return 0


def _ensure_stdio() -> None:
    """无控制台(console=False)打包时 stdout/stderr 可能为 None；mitmdump 等
    依赖真实流。若父进程已把句柄 1/2 重定向到日志文件，则把 sys 流重绑到该 fd；
    否则回退到 os.devnull，避免 print/日志崩溃。"""
    for stream, fileno in ((sys.stdout, 1), (sys.stderr, 2)):
        if stream is not None:
            continue
        try:
            sys.stdout = sys.stderr = os.fdopen(fileno, "w", encoding="utf-8")
            break
        except (OSError, ValueError):
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
            break


def _dispatch_engine(argv: list[str]) -> int:
    # 被动模式：--passive / --mode=passive 交给 sniffer。
    mode = None
    for index, arg in enumerate(argv):
        if arg in ("--passive", "--mode=passive"):
            mode = "passive"
            break
        if arg == "--mode" and index + 1 < len(argv) and argv[index + 1] == "passive":
            mode = "passive"
            break
    if mode == "passive":
        from rf4_core.sniffer import run_passive

        return run_passive(argv)
    from rf4_core.launcher import main as launcher_main

    return launcher_main(argv)


def _main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # 兼容既有 launcher 的引擎自举：DESKMON_ENGINE_MODE=1 时扮演 mitmdump。
    if os.environ.get("DESKMON_ENGINE_MODE") == "1":
        _ensure_stdio()
        from mitmproxy.tools import main as mitm_main

        mitm_main.mitmdump()
        return 0

    if args and args[0] == "--role":
        role = args[1] if len(args) > 1 else ""
        rest = args[2:]
        if role == "engine":
            _ensure_stdio()
            return _dispatch_engine(rest)
        if role == "overlay":
            return _dispatch_overlay()
        if role == "tray":
            return _dispatch_tray(args)
        print(f"[rf4-all] unknown role: {role!r}", file=sys.stderr)
        return 2

    return _dispatch_tray(args)


if __name__ == "__main__":
    raise SystemExit(_main())