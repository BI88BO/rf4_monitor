from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core.protocol import (
    build_request_envelope,
    pack_arg_header,
    pack_guid_marker,
    pack_guid_raw,
    pack_marked_u32,
    pack_object_header,
    pack_short_string,
    parse_envelope,
    parse_fish_setup_push,
    parse_fight_pull_request,
)


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _build_setup_payload(
    *,
    pre_flag_floats: tuple[float, ...] = (),
    post_flag_floats: tuple[float, ...] = (),
    include_flag: bool = True,
    flag_value: int = 1,
    trailing: bytes = b"",
) -> bytes:
    """Build a fish_setup_push payload.

    Layout after weight (0x30): 0x34 float, 0x38 float, 0x3C bool,
    then 0x40..0x70 floats (mirrors the disassembled gkfghccolil layout).
    """
    flag_byte = bytes([flag_value]) if include_flag else b""
    return (
        pack_arg_header(b"507", 1)
        + pack_guid_marker("11111111-1111-1111-1111-111111111111")
        + pack_object_header(123)
        + pack_guid_raw("22222222-2222-2222-2222-222222222222")
        + pack_short_string("perch")
        + bytes([4])
        + struct.pack("<f", 1.25)
        + pack_u32(262)
        + struct.pack("<" + "f" * len(pre_flag_floats), *pre_flag_floats)
        + flag_byte
        + struct.pack("<" + "f" * len(post_flag_floats), *post_flag_floats)
        + trailing
    )


class ParseFishSetupPushTests(unittest.TestCase):
    def setUp(self) -> None:
        from rf4_core.protocol import get_profile

        self.profile = get_profile("4.0.24799")

    def _parse(self, payload: bytes):
        envelope = parse_envelope(
            build_request_envelope(
                call_id=10,
                main_cmd=self.profile.fishing_main_cmd,
                sub_cmd=self.profile.fish_setup_push_sub_cmd,
                payload=payload,
            )
        )
        assert envelope is not None
        return parse_fish_setup_push(envelope, self.profile)

    def test_parses_base_fields(self) -> None:
        setup = self._parse(_build_setup_payload())
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.fish_key, "perch")
        self.assertEqual(setup.weight_hint_raw, 262)
        self.assertAlmostEqual(setup.length_hint, 1.25)
        self.assertEqual(setup.setup_enum, 4)

    def test_flag_byte_read_as_bool(self) -> None:
        setup = self._parse(_build_setup_payload())
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertTrue(setup.flag_byte)

    def test_flag_zero_reads_as_false(self) -> None:
        payload = _build_setup_payload(flag_value=0)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertFalse(setup.flag_byte)

    def test_float_group_after_flag(self) -> None:
        floats = (0.5, 1.0, 2.0)
        payload = _build_setup_payload(pre_flag_floats=(10.0, 20.0), post_flag_floats=floats)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(
            tuple(round(v, 4) for v in setup.extra_floats), (10.0, 20.0, 0.5, 1.0, 2.0)
        )

    def test_pre_flag_floats_and_flag(self) -> None:
        payload = _build_setup_payload(pre_flag_floats=(10.0, 20.0), flag_value=1)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertTrue(setup.flag_byte)
        self.assertEqual(tuple(round(v, 4) for v in setup.extra_floats), (10.0, 20.0))

    def test_no_extra_bytes_yields_empty_group(self) -> None:
        setup = self._parse(_build_setup_payload())
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.extra_floats, ())
        self.assertTrue(setup.flag_byte)

    def test_truncated_float_ignored(self) -> None:
        payload = _build_setup_payload(pre_flag_floats=(1.0,))[:-2]
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.extra_floats, ())

    def test_missing_flag_byte(self) -> None:
        payload = _build_setup_payload(include_flag=False)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertIsNone(setup.flag_byte)
        self.assertEqual(setup.extra_floats, ())

    def test_trailing_bytes_not_parsed_as_floats(self) -> None:
        # Array (0x78) and later composite fields follow; parser must NOT
        # keep reading floats past the fixed 13-float group.
        trailing = bytes(range(0x30))  # 48 bytes of arbitrary composite data
        payload = _build_setup_payload(post_flag_floats=tuple(range(13)), trailing=trailing)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(len(setup.extra_floats), 15)


class ParseFightPullRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        from rf4_core.protocol import get_profile

        self.profile = get_profile("4.0.24799")

    def _parse(self, payload: bytes):
        envelope = parse_envelope(
            build_request_envelope(
                call_id=10,
                main_cmd=self.profile.fishing_main_cmd,
                sub_cmd=self.profile.fight_pull_sub_cmd,
                payload=payload,
            )
        )
        assert envelope is not None
        return parse_fight_pull_request(envelope, self.profile)

    def test_parses_gear_and_tick(self) -> None:
        payload = (
            pack_arg_header(b"507", 3)
            + pack_guid_marker("5a43c383-1111-1111-1111-111111111111")
            + pack_marked_u32(353)
        )
        pull = self._parse(payload)
        self.assertIsNotNone(pull)
        assert pull is not None
        self.assertEqual(pull.fishing_gear_id, "5a43c383-1111-1111-1111-111111111111")
        self.assertEqual(pull.tick, 353)

    def test_missing_gear_returns_none(self) -> None:
        payload = pack_arg_header(b"507", 3) + pack_marked_u32(353)
        self.assertIsNone(self._parse(payload))

    def test_other_sub_cmd_returns_none(self) -> None:
        envelope = parse_envelope(
            build_request_envelope(
                call_id=10,
                main_cmd=self.profile.fishing_main_cmd,
                sub_cmd=self.profile.fight_load_sub_cmd,
                payload=pack_arg_header(b"507", 3),
            )
        )
        assert envelope is not None
        self.assertIsNone(parse_fight_pull_request(envelope, self.profile))


class FightPullAssociationTests(unittest.TestCase):
    def test_association_text(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge
        from rf4_core.protocol import FishSetupMeta, get_profile

        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
            rf4_event_bridge_port=0,
        )
        prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        try:
            bridge = RF4ChatBridge()
            session = FlowSession(profile=get_profile("4.0.24799"))
            setup_id = "72121a20-1111-1111-1111-111111111111"
            gear_id = "5a43c383-1111-1111-1111-111111111111"
            session.fish_setup_cache[setup_id] = FishSetupMeta(
                fish_setup_id=setup_id,
                fish_key="piksha",
                weight_hint_raw=4585,
            )
            session.fish_setup_by_gear[gear_id] = setup_id
            session.fight_fish_by_gear[gear_id] = setup_id
            session.fight_distance_by_gear[gear_id] = 30.9
            payload = (
                pack_arg_header(b"507", 3)
                + pack_guid_marker(gear_id)
                + pack_marked_u32(353)
            )
            text = bridge._format_fight_pull_payload(session, payload)
            self.assertIn("钓组=5a43c383", text)
            self.assertIn("鱼编号=72121a20", text)
            self.assertIn("鱼=黑线鳕", text)
            self.assertIn("重量=4.585 公斤", text)
            self.assertIn("出线=30.9米", text)
            self.assertIn("序号=353", text)
        finally:
            bridge_mod.ctx = prev_ctx


if __name__ == "__main__":
    unittest.main()