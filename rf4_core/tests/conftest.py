"""测试全局配置。"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# 测试默认不写生产浮窗库：未显式指定 rf4_overlay_db 的用例统一写到临时库。
# 否则跑一次测试就会往用户的浮窗事件库里灌 reset/来鱼等事件，实机浮窗会被
# 清屏或弹出假事件（曾导致"跑测试后空闲竿从浮窗消失"的误判）。
_TEST_OVERLAY_DB = Path(tempfile.gettempdir()) / "rf4_tests_overlay_events.sqlite3"


def pytest_configure(config) -> None:
    from rf4_core import bridge as bridge_mod
    from rf4_core.bridge import RF4ChatBridge

    original = RF4ChatBridge._overlay_db_path

    def _overlay_db_path(self):
        raw = getattr(bridge_mod.ctx.options, "rf4_overlay_db", "") or ""
        if raw.strip():
            return original(self)
        return _TEST_OVERLAY_DB

    RF4ChatBridge._overlay_db_path = _overlay_db_path
