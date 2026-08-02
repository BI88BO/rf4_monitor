# -*- mode: python ; coding: utf-8 -*-
"""RF4Monitor 引擎统一入口（打包专用）。

- launcher 模式（默认）：执行 rf4_monitor 的 launcher main。
- engine 模式（RF4_ENGINE_MODE=1）：以本 exe 扮演 mitmdump 引擎，加载 -s 脚本。
"""
import os
import sys


def _engine() -> int:
    from mitmproxy.tools import main as mitm_main

    mitm_main.mitmdump()
    return 0


def _launcher() -> int:
    from rf4_core.launcher import main as launcher_main

    return launcher_main()


if __name__ == "__main__":
    if os.environ.get("RF4_ENGINE_MODE") == "1":
        code = _engine()
    else:
        code = _launcher()
    raise SystemExit(code)