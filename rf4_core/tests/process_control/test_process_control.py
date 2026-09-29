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
    def test_hotkey_defaults_to_f8_and_is_normalized(self) -> None:
        self.assertEqual(SuspendConfig().hotkey, "F8")
        self.assertEqual(SuspendConfig.from_dict({"hotkey": "f9"}).hotkey, "F9")
        self.assertEqual(SuspendConfig.from_dict({"hotkey": "  "}).hotkey, "F8")

    def test_load_reads_process_suspend_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf4_config.json"
            path.write_text(
                json.dumps(
                    {
                        "process_suspend": {
                            "enabled": False,
                            "process_names": ["Game.exe"],
                            "hotkey": "f6",
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = SuspendConfig.load(path)
        self.assertFalse(config.enabled)
        self.assertEqual(config.process_names, ("game.exe",))
        self.assertEqual(config.hotkey, "F6")

    def test_load_ignores_legacy_keys(self) -> None:
        # 倒计时循环和来鱼自动解除都已废弃，旧配置键留着也不能生效。
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf4_config.json"
            path.write_text(
                json.dumps(
                    {
                        "process_suspend": {
                            "loop_enabled": True,
                            "countdown_seconds": 60,
                            "rehang_delay_seconds": 0.05,
                            "resume_on_fish": True,
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = SuspendConfig.load(path)
        self.assertEqual(config, SuspendConfig())
        self.assertFalse(hasattr(config, "loop_enabled"))
        self.assertFalse(hasattr(config, "resume_on_fish"))

    def test_load_uses_defaults_for_missing_or_invalid_file(self) -> None:
        self.assertEqual(
            SuspendConfig.load(Path("missing.json")),
            SuspendConfig(),
        )


class SuspendLoopTests(unittest.TestCase):
    def _loop(self, process):
        return SuspendLoop(process, SuspendConfig())

    def test_toggle_suspends_and_resumes(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        self.assertTrue(loop.toggle())
        self.assertTrue(loop.suspended)
        self.assertEqual(loop.status_text(), "游戏已挂起（F8 恢复）")
        self.assertTrue(loop.suspended)
        self.assertEqual(process.resume_calls, 0)
        self.assertTrue(loop.toggle())
        self.assertEqual(process.resume_calls, 1)

    def test_incoming_thaws_and_arms_the_bite_freeze(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request("release", "2号杆来鱼")
        loop.tick()
        self.assertFalse(loop.suspended)
        self.assertTrue(loop.armed)
        self.assertEqual(process.resume_calls, 1)
        self.assertEqual(loop.status_text(), "等待咬钩，咬钩自动挂起")

    def test_bite_after_incoming_freezes_and_notes_the_rod(self) -> None:
        # 完整流程：冻着 → 来鱼解冻 → 咬钩冻回，鱼停在咬钩那一帧等拉杆。
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request("release", "2号杆来鱼")
        loop.request("freeze", "2号杆咬钩")
        loop.tick()
        self.assertTrue(loop.suspended)
        self.assertFalse(loop.armed)
        self.assertEqual(process.suspend_calls, 2)
        self.assertEqual(
            loop.status_text(), "游戏已挂起 · 2号杆咬钩，按 F8 拉杆"
        )

    def test_actions_only_run_on_the_suspend_thread_tick(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request("release", "2号杆来鱼")
        self.assertTrue(loop.suspended)
        self.assertEqual(process.resume_calls, 0)
        loop.tick()
        self.assertEqual(process.resume_calls, 1)

    def test_bite_never_freezes_unless_we_armed_it(self) -> None:
        # 玩家没挂起过（或已经自己接管）时，工具绝不自作主张冻住游戏。
        process = _FakeProcess()
        loop = self._loop(process)
        loop.request("freeze", "2号杆咬钩")
        loop.tick()
        self.assertFalse(loop.suspended)
        self.assertEqual(loop.fish_notes, [])
        self.assertEqual(process.suspend_calls, 0)

    def test_incoming_does_not_arm_when_nothing_is_suspended(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.request("release", "2号杆来鱼")
        loop.tick()
        self.assertFalse(loop.armed)
        self.assertEqual(process.resume_calls, 0)
        self.assertEqual(loop.status_text(), "")

    def test_hotkey_during_arming_freezes_and_ends_the_flow(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request("release", "2号杆来鱼")
        loop.tick()
        # 待命时按热键＝玩家自己冻住游戏，之后咬钩不再自动冻（已经在冻了）。
        self.assertTrue(loop.toggle())
        self.assertTrue(loop.suspended)
        self.assertFalse(loop.armed)
        loop.request("freeze", "2号杆咬钩")
        loop.tick()
        self.assertEqual(loop.fish_notes, [])
        self.assertEqual(process.suspend_calls, 2)

    def test_disarm_drops_the_arming(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request("release", "2号杆来鱼")
        loop.request("disarm", "")
        loop.tick()
        self.assertFalse(loop.armed)
        self.assertEqual(loop.status_text(), "")

    def test_incoming_does_not_thaw_a_bite_freeze(self) -> None:
        # 别的竿来鱼不能把"为拉杆冻住"的游戏解冻，否则咬钩的鱼就跑掉了。
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request("release", "2号杆来鱼")
        loop.request("freeze", "2号杆咬钩")
        loop.tick()
        loop.request("release", "1号杆来鱼")
        loop.tick()
        self.assertTrue(loop.suspended)
        self.assertFalse(loop.armed)
        self.assertEqual(process.resume_calls, 1)

    def test_extra_bites_are_noted_while_frozen_for_the_pull(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.request("release", "2号杆来鱼")
        loop.request("freeze", "2号杆咬钩")
        loop.request("freeze", "1号杆咬钩")
        loop.tick()
        self.assertEqual(process.suspend_calls, 2)
        self.assertEqual(
            loop.status_text(),
            "游戏已挂起 · 2号杆咬钩、1号杆咬钩，按 F8 拉杆",
        )

    def test_fish_notes_accumulate_without_duplicates(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.note_fish("2号杆咬钩")
        loop.note_fish("1号杆来鱼")
        loop.note_fish("2号杆咬钩")
        loop.note_fish("")
        self.assertEqual(
            loop.status_text(),
            "游戏已挂起 · 2号杆咬钩、1号杆来鱼，按 F8 拉杆",
        )

    def test_notes_clear_on_resume_and_on_next_suspend(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.note_fish("2号杆咬钩")
        loop.stop()
        self.assertEqual(loop.fish_notes, [])
        loop.start()
        loop.note_fish("3号杆来鱼")
        loop.start()
        self.assertEqual(loop.fish_notes, [])

    def test_detach_forgets_notes_but_keeps_suspension(self) -> None:
        process = _FakeProcess()
        loop = self._loop(process)
        loop.start()
        loop.note_fish("2号杆咬钩")
        loop.detach()
        self.assertEqual(loop.fish_notes, [])
        self.assertTrue(loop.suspended)
        self.assertEqual(process.resume_calls, 0)

    def test_failed_start_reports_error_until_next_success(self) -> None:
        process = _FakeProcess(suspend_ok=False)
        loop = self._loop(process)
        self.assertFalse(loop.toggle())
        self.assertEqual(
            loop.status_text(), "未找到 rf4_x64.exe 或挂起失败，游戏启动后再按 F8"
        )

        process.suspend_ok = True
        self.assertTrue(loop.toggle())
        self.assertEqual(loop.status_text(), "游戏已挂起（F8 恢复）")

    def test_status_text_reports_the_key_actually_bound(self) -> None:
        # 首选键被占用时热键会顺延，状态文本必须跟着显示真正绑上的键。
        process = _FakeProcess()
        loop = self._loop(process)
        loop.hotkey_label = "F9"
        loop.start()
        self.assertEqual(loop.status_text(), "游戏已挂起（F9 恢复）")
        process.suspend_ok = False
        loop.suspended = False
        loop.start()
        self.assertEqual(
            loop.status_text(), "未找到 rf4_x64.exe 或挂起失败，游戏启动后再按 F9"
        )

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

    def test_default_key_comes_first_then_reference_fallbacks(self) -> None:
        self.assertEqual(
            GlobalHotkey("F8")._candidates(), ("F8", "F9", "F6", "F5", "F7")
        )

    def test_custom_key_is_prepended_without_duplicates(self) -> None:
        self.assertEqual(
            GlobalHotkey("f9")._candidates(), ("F9", "F8", "F6", "F5", "F7")
        )

    def test_bound_key_starts_empty(self) -> None:
        self.assertEqual(GlobalHotkey("F8").bound_key, "")


@unittest.skipUnless(os.name == "nt", "Windows hotkey API required")
class GlobalHotkeyApiTests(unittest.TestCase):
    def test_post_thread_message_uses_user32(self) -> None:
        _configure_hotkey_api()
        user32 = ctypes.windll.user32
        self.assertEqual(
            tuple(user32.PostThreadMessageW.argtypes),
            (wt.DWORD, wt.UINT, wt.WPARAM, wt.LPARAM),
        )
