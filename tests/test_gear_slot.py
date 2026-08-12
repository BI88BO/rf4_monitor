from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core import bridge as bridge_mod
from rf4_core.bridge import FlowSession, RF4ChatBridge
from rf4_core.protocol import get_profile


def _session_with_slots(slots: dict[int, str]) -> tuple[RF4ChatBridge, FlowSession]:
    options = SimpleNamespace(
        rf4_verbose_logging=False,
        rf4_log_telemetry=True,
        rf4_telemetry_categories="all",
        rf4_event_bridge_port=0,
    )
    wrapper = bridge_mod.ctx
    bridge_mod.ctx = SimpleNamespace(options=options)
    bridge = RF4ChatBridge()
    session = FlowSession(profile=get_profile("4.0.24799"))
    session.slot_items.update(slots)
    return bridge, session


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


if __name__ == "__main__":
    unittest.main()