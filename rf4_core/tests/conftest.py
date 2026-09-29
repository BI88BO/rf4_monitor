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
# 同理，装备槽磁盘缓存是实机攒下的竿号映射，测试写/删它等于抹掉用户的缓存。
_TEST_ROD_SLOT_CACHE = _TEST_OVERLAY_DB.parent / "rf4_tests_rod_slot_cache.json"


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

    original_init = RF4ChatBridge.__init__

    def __init__(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._rod_slot_cache_path = _TEST_ROD_SLOT_CACHE

    RF4ChatBridge.__init__ = __init__

    # token 缓存里是实机攒下的登录 token（服务器 -> token）。切服/bootstrap 测试
    # 会写它，跑一遍测试就把假 token 混进真映射，重连时拿错 token 去对齐 RC4。
    # 两个函数的 path 是默认参数（定义时绑定），只能改 __defaults__。
    from rf4_core import sniffer as sniffer_mod

    _TEST_TOKEN_CACHE = _TEST_OVERLAY_DB.parent / "rf4_tests_token_cache.json"
    sniffer_mod._load_cached_tokens.__defaults__ = (_TEST_TOKEN_CACHE,)
    sniffer_mod._save_cached_token.__defaults__ = (_TEST_TOKEN_CACHE,)
