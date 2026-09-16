"""rf4_core.bridge：装备槽位（11/2）映射测试。"""
from __future__ import annotations

import json
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from rf4_core import bridge as bridge_mod
from rf4_core.bridge import FlowSession, RF4ChatBridge
from rf4_core.protocol import (
    build_response_envelope,
    get_profile,
    pack_u16,
    pack_u32,
)


def _session_with_slots(slots: dict[int, str]) -> tuple[RF4ChatBridge, FlowSession]:
    options = SimpleNamespace(
        rf4_verbose_logging=False,
        rf4_log_telemetry=True,
        rf4_telemetry_categories="all",
    )
    wrapper = bridge_mod.ctx
    bridge_mod.ctx = SimpleNamespace(options=options)
    bridge = RF4ChatBridge()
    session = FlowSession(profile=get_profile("4.0.24799"))
    session.slot_items.update(slots)
    return bridge, session


def _slot_payload(slot_type: int, item_guid: str) -> bytes:
    """11/2 单条槽位响应的 payload：typed_list(65)[object(136){u16 type; guid}]。"""
    entry = (
        b"\x01" + pack_u32(136)
        + pack_u16(slot_type)
        + uuid.UUID(item_guid).bytes_le
    )
    return b"\x03\x02" + b"65" + pack_u16(1) + entry


class GearSlotTextTests(unittest.TestCase):
    def tearDown(self) -> None:
        bridge_mod.ctx = getattr(self, "_prev_ctx", None)

    def test_slot_type_1_maps_to_first_rod(self) -> None:
        bridge, session = _session_with_slots({1: "gear-a"})
        self.assertEqual(bridge._gear_slot_text(session, "gear-a"), "1号杆")

    def test_extended_slot_type_20_maps_to_rod_four(self) -> None:
        bridge, session = _session_with_slots({20: "gear-b"})
        self.assertEqual(bridge._gear_slot_text(session, "gear-b"), "4号杆")

    def test_unknown_slot_type_shows_no_rod_number(self) -> None:
        bridge, session = _session_with_slots({4: "gear-c"})
        self.assertEqual(bridge._gear_slot_text(session, "gear-c"), "")

    def test_active_slot_noise_does_not_shadow_real_slot(self) -> None:
        # 回归：同一把竿的 GUID 同时出现在 slot_type=4(当前活动位，噪声)和
        # slot_type=1(真实快捷键槽)时，若 dict 顺序先命中 4，旧逻辑直接返回
        # ""，导致有竿号的竿被判成"手持竿"。必须跳过未收录槽位继续找。
        gear = "11111111-1111-1111-1111-111111111111"
        bridge, session = _session_with_slots({4: gear, 1: gear})
        self.assertEqual(bridge._gear_slot_text(session, gear), "1号杆")
        bridge, session = _session_with_slots({1: gear, 4: gear})
        self.assertEqual(bridge._gear_slot_text(session, gear), "1号杆")

    def test_missing_gear_returns_empty(self) -> None:
        bridge, session = _session_with_slots({1: "gear-a"})
        self.assertEqual(bridge._gear_slot_text(session, None), "")

    def test_gear_not_in_slots_returns_empty(self) -> None:
        bridge, session = _session_with_slots({1: "gear-a"})
        self.assertEqual(bridge._gear_slot_text(session, "gear-zzz"), "")


class SwitchSlotUpdateTests(unittest.TestCase):
    """11/2(切换装备槽位)增量更新：中途换杆后竿号映射必须跟上。"""

    def setUp(self) -> None:
        self.bridge, self.session = _session_with_slots(
            {1: "11111111-1111-1111-1111-111111111111"}
        )

    def _feed_switch(self, call_id: int, slot_type: int, item_guid: str) -> None:
        self.session.slot_request_calls[call_id] = 2
        plain = build_response_envelope(
            call_id=call_id, payload=_slot_payload(slot_type, item_guid)
        )
        self.bridge._remember_server_slot_items(self.session, plain, sub_cmd=2)

    def test_switch_updates_shortcut_slot_mapping(self) -> None:
        # 换杆场景：新钓组进 1 号槽，玩家按键切换时 11/2 上报该槽内容。
        new_gear = "22222222-2222-2222-2222-222222222222"
        self._feed_switch(7, 1, new_gear)
        self.assertEqual(self.session.slot_items[1], new_gear)
        # 旧钓组已不在槽内，新钓组正确显示竿号。
        self.assertEqual(
            self.bridge._gear_slot_text(self.session, new_gear), "1号杆"
        )
        self.assertEqual(
            self.bridge._gear_slot_text(
                self.session, "11111111-1111-1111-1111-111111111111"
            ),
            "",
        )

    def test_switch_ignores_active_slot_noise(self) -> None:
        # slot_type=4 是"当前活动位"，不是快捷键编号，不得写入映射。
        gear = "33333333-3333-3333-3333-333333333333"
        self._feed_switch(8, 4, gear)
        self.assertNotIn(4, self.session.slot_items)
        self.assertEqual(
            self.bridge._gear_slot_text(self.session, gear), ""
        )

    def test_switch_ignores_unmapped_slot_types(self) -> None:
        gear = "44444444-4444-4444-4444-444444444444"
        self._feed_switch(9, 50, gear)
        self.assertNotIn(50, self.session.slot_items)


class FullSlotMappingTests(unittest.TestCase):
    """11/1 完整映射响应中的空槽不得覆盖已确认的竿位。"""

    def test_empty_full_slot_response_preserves_known_mapping(self) -> None:
        bridge, session = _session_with_slots({1: "11111111-1111-1111-1111-111111111111"})
        session.slot_request_calls[12] = 1
        plain = build_response_envelope(
            call_id=12,
            payload=_slot_payload(1, "00000000-0000-0000-0000-000000000000"),
        )
        bridge._remember_server_slot_items(session, plain, sub_cmd=1)
        self.assertEqual(
            session.slot_items[1], "11111111-1111-1111-1111-111111111111"
        )
        self.assertEqual(
            bridge._gear_slot_text(
                session, "11111111-1111-1111-1111-111111111111"
            ),
            "1号杆",
        )


class RodSlotCacheTests(unittest.TestCase):
    """装备槽位磁盘缓存：中途开启抓包时恢复竿号映射。"""

    def setUp(self) -> None:
        self._prev_ctx = getattr(bridge_mod, "ctx", None)
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemlemetry_categories="all",
        )
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self._cache_path = self.bridge._rod_slot_cache_path

    def tearDown(self) -> None:
        bridge_mod.ctx = self._prev_ctx
        if self._cache_path.exists():
            self._cache_path.unlink(missing_ok=True)

    def test_save_and_restore_slot_items(self) -> None:
        session = FlowSession(profile=get_profile("4.0.24799"))
        session.slot_items[1] = "11111111-1111-1111-1111-111111111111"
        session.slot_items[2] = "22222222-2222-2222-2222-222222222222"
        session.slot_items[3] = "33333333-3333-3333-3333-333333333333"
        self.bridge._save_rod_slot_cache(session)
        self.assertTrue(self._cache_path.exists())

        # 新会话，无槽位映射
        fresh = FlowSession(profile=get_profile("4.0.24799"))
        self.assertNotIn(1, fresh.slot_items)
        self.bridge._restore_rod_slot_cache(fresh)
        self.assertEqual(fresh.slot_items[1], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(fresh.slot_items[2], "22222222-2222-2222-2222-222222222222")
        self.assertEqual(fresh.slot_items[3], "33333333-3333-3333-3333-333333333333")

    def test_restore_skips_unmapped_slot_types(self) -> None:
        """缓存里有未收录的槽位（如 slot_type=4），不应写入 slot_items。"""
        import time as _time
        payload = {
            "schema_version": RF4ChatBridge.ROD_SLOT_CACHE_SCHEMA_VERSION,
            "saved_at": _time.time(),
            "shortcut_items": {"1": "11111111-1111-1111-1111-111111111111", "4": "44444444-4444-4444-4444-444444444444"},
        }
        self._cache_path.write_text(json.dumps(payload), encoding="utf-8")
        session = FlowSession(profile=get_profile("4.0.24799"))
        self.bridge._restore_rod_slot_cache(session)
        self.assertIn(1, session.slot_items)
        self.assertNotIn(4, session.slot_items)

    def test_restore_rejects_stale_cache(self) -> None:
        """超过30天的缓存应被忽略。"""
        payload = {
            "schema_version": RF4ChatBridge.ROD_SLOT_CACHE_SCHEMA_VERSION,
            "saved_at": 0,  # 1970-01-01，远超30天
            "shortcut_items": {"1": "11111111-1111-1111-1111-111111111111"},
        }
        self._cache_path.write_text(json.dumps(payload), encoding="utf-8")
        session = FlowSession(profile=get_profile("4.0.24799"))
        self.bridge._restore_rod_slot_cache(session)
        self.assertNotIn(1, session.slot_items)

    def test_restore_rejects_wrong_schema(self) -> None:
        """schema 版本不匹配的缓存应被忽略。"""
        payload = {
            "schema_version": 999,
            "saved_at": 0,
            "shortcut_items": {"1": "11111111-1111-1111-1111-111111111111"},
        }
        self._cache_path.write_text(json.dumps(payload), encoding="utf-8")
        session = FlowSession(profile=get_profile("4.0.24799"))
        self.bridge._restore_rod_slot_cache(session)
        self.assertNotIn(1, session.slot_items)

    def test_save_only_persisted_shortcut_slots(self) -> None:
        """非快捷键槽位（如 slot_type=4）不应写入缓存。"""
        session = FlowSession(profile=get_profile("4.0.24799"))
        session.slot_items[1] = "11111111-1111-1111-1111-111111111111"
        session.slot_items[4] = "44444444-4444-4444-4444-444444444444"
        self.bridge._save_rod_slot_cache(session)
        raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
        shortcut_items = raw.get("shortcut_items", {})
        self.assertIn("1", shortcut_items)
        self.assertNotIn("4", shortcut_items)
