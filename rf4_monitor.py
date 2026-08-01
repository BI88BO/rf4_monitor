"""RF4 Monitor 兼容入口。

本文件保留原单文件 rf4_monitor.py 的双重角色：

- 作为 mitmdump addon 被加载（-s rf4_monitor.py）时，暴露 ``addons = [RF4ChatBridge()]``
- 作为独立 CLI 运行时，调用 ``main()`` 启动 launcher（hosts/证书/mitmdump）

实际实现已拆分到 rf4_core/ 包：
  launcher、protocol、fish_labels、console、bridge
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
from rf4_core.launcher import main

if __name__ != "__main__":
    addons = [RF4ChatBridge()]
else:
    addons = []

if __name__ == "__main__":
    raise SystemExit(main())
