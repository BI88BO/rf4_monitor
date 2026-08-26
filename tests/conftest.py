"""测试全局加速：默认跳过启动时的真实部件目录解密（多文件×多变体，耗时）。

需要验证解密链路本身的测试用 pytest.mark.real_cache_decrypt 标记，
或在其 setUp 中自行恢复 RF4ChatBridge.ALLOW_STARTUP_CACHE_DECRYPT。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core.bridge import RF4ChatBridge


def pytest_configure(config):
    RF4ChatBridge.ALLOW_STARTUP_CACHE_DECRYPT = False


@pytest.fixture(autouse=True)
def _no_startup_cache_decrypt(request, monkeypatch):
    if request.node.get_closest_marker("real_cache_decrypt"):
        yield
        return
    monkeypatch.setattr(
        RF4ChatBridge, "ALLOW_STARTUP_CACHE_DECRYPT", False, raising=False
    )
    yield
