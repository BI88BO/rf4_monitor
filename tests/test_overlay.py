from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_OVERLAY_PATH = Path(__file__).resolve().parents[1] / "rf4_overlay.pyw"
_spec = importlib.util.spec_from_file_location("rf4_overlay", _OVERLAY_PATH)
overlay_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(overlay_mod)
Overlay = overlay_mod.Overlay


def _empty_overlay() -> Overlay:
    """Build an Overlay instance without touching Tk, wired to record calls."""
    calls: list[tuple] = []
    ov = object.__new__(Overlay)

    def record_self(gear_slot: str = "", text: str = "", clear_after: int = 0) -> None:
        calls.append(("self", gear_slot, text, clear_after))

    def record_generic(text: str) -> None:
        calls.append(("generic", text))

    def record_anticheat(text: str) -> None:
        calls.append(("anticheat", text))

    def record_reset() -> None:
        calls.append(("reset",))

    def record_show(gear_slot: str = "", text: str = "") -> None:
        calls.append(("self", gear_slot, text, 0))

    ov._show_self_event = record_self
    ov._show_generic = record_generic
    ov._show_anticheat = record_anticheat
    ov._reset_to_idle = record_reset
    ov.calls = calls
    return ov


class OverlayDatagramRoutingTests(unittest.TestCase):
    def test_self_events_route_to_show_self_event(self) -> None:
        ov = _empty_overlay()
        payload = json.dumps(
            {
                "event": "fish_incoming",
                "gear_slot": "2",
                "text": "【我自己】：有鱼过来了",
            },
            ensure_ascii=False,
        )
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov.calls, [("self", "2", "【我自己】：有鱼过来了", 0)])

    def test_kept_events_clear_after_three_seconds(self) -> None:
        ov = _empty_overlay()
        payload = json.dumps(
            {"event": "fish_kept", "gear_slot": "1", "text": "入护了"},
            ensure_ascii=False,
        )
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov.calls, [("self", "1", "入护了", 3000)])

    def test_chat_and_telemetry_route_to_generic(self) -> None:
        ov = _empty_overlay()
        ov._handle_datagram(b'{"event": "chat", "text": "hello"}')
        ov._handle_datagram(b'{"event": "telemetry", "text": "w1"}')
        self.assertEqual(ov.calls, [("generic", "hello"), ("generic", "w1")])

    def test_reset_routes_to_reset_to_idle(self) -> None:
        ov = _empty_overlay()
        ov._handle_datagram(b'{"event": "reset", "text": ""}')
        self.assertEqual(ov.calls, [("reset",)])

    def test_anticheat_routes_to_show_anticheat(self) -> None:
        ov = _empty_overlay()
        ov._handle_datagram(b'{"event": "anticheat", "text": "ac"}')
        self.assertEqual(ov.calls, [("anticheat", "ac")])

    def test_garbage_datagram_is_ignored(self) -> None:
        ov = _empty_overlay()
        ov._handle_datagram(b"not-json")
        ov._handle_datagram(b"")
        self.assertEqual(ov.calls, [])


if __name__ == "__main__":
    unittest.main()