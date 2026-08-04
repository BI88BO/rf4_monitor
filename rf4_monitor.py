"""RF4 Monitor 兼容入口。

本文件保留原单文件 rf4_monitor.py 的双重角色：

- 作为 mitmdump addon 被加载（-s rf4_monitor.py）时，暴露 ``addons = [RF4ChatBridge()]``
- 作为独立 CLI 运行时，调用 ``main()`` 启动 launcher（hosts/证书/mitmdump）

运行模式：
- ``--mode passive`` 或 ``--passive``：被动抓包模式（读取明文 token 并解密，不改包）
- ``--mode proxy`` 或 ``--proxy``（默认）：代理模式（hosts/证书/mitmdump）

实际实现已拆分到 rf4_core/ 包：
  launcher、protocol、fish_labels、console、bridge、sniffer
"""

from __future__ import annotations

import os
import sys
import types

if __name__ not in sys.modules:
    sys.modules[__name__] = types.ModuleType(__name__)

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

from rf4_core.bridge import RF4ChatBridge

if __name__ != "__main__":
    addons = [RF4ChatBridge()]
else:
    addons = []


def _requested_passive(argv: list[str]) -> bool:
    """Return True if a passive mode flag appears, False otherwise (proxy default)."""
    for index, arg in enumerate(argv):
        if arg in ("--passive", "--mode=passive"):
            return True
        if arg in ("--proxy", "--mode=proxy"):
            return False
        if arg == "--mode":
            if index + 1 < len(argv) and argv[index + 1] == "passive":
                return True
            return False
    return False


if __name__ == "__main__":
    argv = list(sys.argv[1:])
    if _requested_passive(argv):
        from rf4_core.sniffer import run_passive

        raise SystemExit(run_passive(argv))
    from rf4_core.launcher import main

    raise SystemExit(main())
