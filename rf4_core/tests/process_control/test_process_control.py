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
    def __init__(self, suspend_ok: bool = True, resume_ok: bool = True) -> None:
        self.suspend_ok = suspend_ok
        self.resume_ok = resume_ok
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
        if not self.resume_ok:
            return False
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
                            "resume_on_fish": False,
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = SuspendConfig.load(path)
        self.assertFalse(config.enabled)
        self.assertEqual(config.process_names, ("game.exe",))
        self.assertFalse(config.resume_on_fish)

    def test_load_ignores_legacy_loop_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf4_config.json"
            path.write_text(
                json.dumps(
                    {
                        "process_suspend": {
                            "loop_enabled": True,
                            "countdown_seconds": 60,
                            "rehang_delay_seconds": 0.05,
                            "lock_cycle_on_fish": True,
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = SuspendConfig.load(path)
        self.assertTrue(config.enabled)
        self.assertTrue(config.resume_on_fish)

    def test_load_uses_defaults_for_missing_or_invalid_file(self) -> None:
        self.assertEqual(
            SuspendConfig.load(Path("missing.json")),
            SuspendConfig(),
        )


class SuspendLoopTests(unittest.TestCase):
    def _loop(self, process, resume_on_fish=True):
        return SuspendLoop(process, SuspendConfig(resume_on_fish=resume_on_fish))

    def test_toggle_suspends_and_resumes(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        self.assertTrue(loop.toggle())
        self.assertTrue(loop.suspended)
        self.assertEqual(loop.status_text(), "已挂起")
        loop.tick()
        self.assertTrue(loop.suspended)
        self.assertEqual(process.resume_calls, 0)
        self.assertTrue(loop.toggle())
        self.assertEqual(process.resume_calls, 1)

    def test_request_release_defers_resume_until_tick(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request_release()
        self.assertTrue(loop.suspended)
        self.assertEqual(process.resume_calls, 0)
        loop.tick()
        self.assertFalse(loop.suspended)
        self.assertEqual(process.resume_calls, 1)

    def test_request_release_is_a_noop_when_disabled(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process, resume_on_fish=False)
        loop.start()
        loop.request_release()
        loop.tick()
        self.assertTrue(loop.suspended)
        self.assertEqual(process.resume_calls, 0)

    def test_request_release_without_suspension_is_a_noop(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.request_release()
        loop.tick()
        self.assertFalse(loop.suspended)
        self.assertEqual(process.resume_calls, 0)

    def test_detach_keeps_suspension_for_manual_resume(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.detach()
        self.assertTrue(loop.suspended)
        self.assertEqual(process.resume_calls, 0)

    def test_failed_start_reports_error_until_next_success(self) -> None:
        process = _FakeProcess(suspend_ok=False)
        loop = self._loop(process)
        self.assertFalse(loop.toggle())
        self.assertEqual(loop.status_text(), "未找到 rf4_x64.exe 或挂起失败")

        process.suspend_ok = True
        self.assertTrue(loop.toggle())
        self.assertEqual(loop.status_text(), "已挂起")

    def test_failed_resume_reports_error(self) -> None:
        process = _FakeProcess(resume_ok=False)
        loop = self._loop(process)
        self.assertTrue(loop.toggle())
        self.assertFalse(loop.toggle())
        self.assertEqual(loop.status_text(), "游戏进程恢复失败")

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
