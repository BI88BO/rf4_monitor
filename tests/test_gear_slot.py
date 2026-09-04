from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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


if __name__ == "__main__":
    unittest.main()