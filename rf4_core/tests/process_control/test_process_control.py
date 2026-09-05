"""进程挂起状态机与配置解析测试。"""
from __future__ import annotations

import ctypes
import json
import tempfile
import unittest
import os
from pathlib import Path
from ctypes import wintypes as wt

from rf4_core.process_control import (
    _configure_hotkey_api,
    GlobalHotkey,
    ProcessSuspender,
    SuspendConfig,
    SuspendLoop,
)


class _FakeProcess:
    def __init__(self, suspend_ok: bool = True) -> None:
        self.suspend_ok = suspend_ok
        self.suspend_calls = 0
        self.resume_calls = 0
        self.suspended = False

    def suspend(self) -> bool:
        if not self.suspend_ok:
            return False
        self.suspend_calls += 1
        self.suspended = True
        return True

    def resume(self) -> bool:
        self.resume_calls += 1
        self.suspended = False
        return True


class SuspendConfigTests(unittest.TestCase):
    def test_load_reads_process_suspend_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf4_config.json"
            path.write_text(
                json.dumps(
                    {
                        "process_suspend": {
                            "enabled": False,
                            "process_names": ["Game.exe"],
                            "loop_enabled": False,
                            "countdown_seconds": 30,
                            "rehang_delay_seconds": 0.5,
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = SuspendConfig.load(path)
        self.assertFalse(config.enabled)
        self.assertEqual(config.process_names, ("game.exe",))
        self.assertFalse(config.loop_enabled)
        self.assertEqual(config.countdown_seconds, 30.0)
        self.assertEqual(config.rehang_delay_seconds, 0.5)

    def test_load_uses_defaults_for_missing_or_invalid_file(self) -> None:
        self.assertEqual(
            SuspendConfig.load(Path("missing.json")),
            SuspendConfig(countdown_seconds=60.0, rehang_delay_seconds=0.05),
        )


class SuspendLoopTests(unittest.TestCase):
    def _loop(self, process, clock, countdown=10.0, delay=2.0, loop=True):
        return SuspendLoop(
            process,
            SuspendConfig(
                loop_enabled=loop,
                countdown_seconds=countdown,
                rehang_delay_seconds=delay,
            ),
            clock=clock,
        )

    def test_toggle_without_loop_stays_suspended(self) -> None:
        now = [100.0]
        process = _FakeProcess()
        loop = self._loop(process, lambda: now[0], loop=False)
        self.assertTrue(loop.toggle())
        self.assertTrue(loop.suspended)
        self.assertFalse(loop.active)
        self.assertEqual(loop.status_text(), "已挂起")
        loop.tick()
        self.assertTrue(loop.suspended)
        self.assertTrue(loop.toggle())
        self.assertEqual(process.resume_calls, 1)

    def test_loop_counts_down_resumes_and_rehangs(self) -> None:
        now = [200.0]
        process = _FakeProcess()
        loop = self._loop(process, lambda: now[0], countdown=10.0, delay=2.0)
        self.assertTrue(loop.start())
        self.assertEqual(loop.status_text(), "已挂起 10")
        now[0] += 10.1
        loop.tick()
        self.assertFalse(loop.suspended)
        self.assertEqual(loop.status_text(), "待挂起 2")
        now[0] += 2.1
        loop.tick()
        self.assertTrue(loop.suspended)
        self.assertEqual(loop.status_text(), "已挂起 10")
        self.assertEqual(process.resume_calls, 1)
        self.assertEqual(process.suspend_calls, 2)

    def test_detach_keeps_suspension_for_manual_resume(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process, lambda: 0.0)
        loop.start()
        loop.detach()
        self.assertTrue(loop.suspended)
        self.assertFalse(loop.active)
        self.assertEqual(process.resume_calls, 0)

    def test_process_name_is_normalized_for_toolhelp_lookup(self) -> None:
        process = ProcessSuspender(("RF4_x64.EXE",))
        self.assertEqual(process.process_names, ("rf4_x64.exe",))


class GlobalHotkeyParsingTests(unittest.TestCase):
    def test_parse_plain_f8(self) -> None:
        self.assertEqual(GlobalHotkey._key_parts("F8"), (0, 0x77))

    def test_parse_control_f8(self) -> None:
        self.assertEqual(GlobalHotkey._key_parts("Ctrl+F8"), (0x0002, 0x77))

    def test_rejects_unknown_key(self) -> None:
        with self.assertRaises(ValueError):
            GlobalHotkey._key_parts("Mouse+Wheel")


@unittest.skipUnless(os.name == "nt", "Windows hotkey API required")
class GlobalHotkeyApiTests(unittest.TestCase):
    def test_post_thread_message_uses_user32(self) -> None:
        _configure_hotkey_api()
        user32 = ctypes.windll.user32
        self.assertEqual(
            tuple(user32.PostThreadMessageW.argtypes),
            (wt.DWORD, wt.UINT, wt.WPARAM, wt.LPARAM),
        )
