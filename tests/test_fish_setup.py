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
    get_profile,
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


class FightStaminaHelpersTests(unittest.TestCase):
    def setUp(self) -> None:
        from rf4_core.bridge import RF4ChatBridge

        self.bridge = RF4ChatBridge.__new__(RF4ChatBridge)

    def test_stamina_percent_from_second_group(self) -> None:
        groups = ((2.0, 2.0, 0.444, 9.221), (1.0, 69.09, 0.07, 5.1), (0.0, 0.0, 1.0, 26.2))
        self.assertEqual(self.bridge._fight_stamina(groups), 100)

    def test_stamina_percent_half(self) -> None:
        groups = ((0.0, 0.0, 0.0, 0.0), (0.55, 0.0, 0.0, 0.0))
        self.assertEqual(self.bridge._fight_stamina(groups), 50)

    def test_stamina_out_of_range_returns_none(self) -> None:
        groups = ((0.0, 0.0, 0.0, 0.0), (2.0, 0.0, 0.0, 0.0))
        self.assertIsNone(self.bridge._fight_stamina(groups))

    def test_stamina_missing_second_group_returns_none(self) -> None:
        self.assertIsNone(self.bridge._fight_stamina((((2.0, 2.0),),)))

    def test_distance_validation(self) -> None:
        self.assertTrue(self.bridge._is_valid_distance(26.2))
        self.assertTrue(self.bridge._is_valid_distance(88.0))
        self.assertFalse(self.bridge._is_valid_distance(0.0))
        self.assertFalse(self.bridge._is_valid_distance(-10.7))
        self.assertFalse(self.bridge._is_valid_distance(float("nan")))

    def test_sanitize_distance_falls_back_to_last(self) -> None:
        self.assertEqual(self.bridge._sanitize_distance(-10.7, 26.2), 26.2)
        self.assertEqual(self.bridge._sanitize_distance(12.3, 26.2), 12.3)
        self.assertEqual(self.bridge._sanitize_distance(None, 26.2), 26.2)
        self.assertIsNone(self.bridge._sanitize_distance(-1.0, None))


class FightLoadSlimLineTests(unittest.TestCase):
    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge

        self.pack_arg_header = pack_arg_header
        self.pack_guid_marker = pack_guid_marker
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
            rf4_event_bridge_port=0,
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        # 钓组挂到 1 号杆槽位
        self.session.slot_items[1] = "5a43c383-1111-1111-1111-111111111111"

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _payload(self, distance: float, stamina: float = 1.0) -> bytes:
        gear = "5a43c383-1111-1111-1111-111111111111"
        return (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(gear)
            + struct.pack("<4f", 2.0, 2.0, 0.444, 9.221)
            + struct.pack("<4f", stamina, 69.09, 0.07, 5.1)
            + struct.pack("<4f", 0.04, 7.1, 3.9, 0.0)
            + struct.pack("<4f", 0.0, 0.0, 1.0, distance)
            + struct.pack("<4f", 0.0, 12.5, 2.0, 555.0)
        )

    def test_slim_line_with_stamina_and_distance(self) -> None:
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertIn("1号杆", text)
        self.assertIn("体力 100%", text)
        self.assertIn("出线 26.2米", text)
        # 精简：不包含冗余字段
        self.assertNotIn("浮点", text)
        self.assertNotIn("拉力方向", text)
        self.assertNotIn("负载", text)
        self.assertNotIn("序号", text)

    def test_glitch_distance_keeps_last_value(self) -> None:
        self.session.fight_distance_by_gear["5a43c383-1111-1111-1111-111111111111"] = 26.2
        text = self.bridge._format_fight_load_payload(self.session, self._payload(-10.7))
        self.assertIn("出线 26.2米", text)

    def test_handheld_gear_produces_empty_line(self) -> None:
        # 不挂槽位 -> _gear_slot_text 返回 "" -> 行空（手持不显示）
        self.session.slot_items.clear()
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertEqual(text, "")


class FightLoadRecordDistanceTests(unittest.TestCase):
    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge

        self.pack_arg_header = pack_arg_header
        self.pack_guid_marker = pack_guid_marker
        self.gear = "5a43c383-1111-1111-1111-111111111111"
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
            rf4_event_bridge_port=0,
            rf4_show_fish=True,
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        self.session.slot_items[1] = self.gear
        # 阻止遥测重复 emit，专注距离记录
        self.bridge._log_telemetry = lambda cat, text: None

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _frame(self, distance: float) -> bytes:
        payload = (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + struct.pack("<4f", 2.0, 2.0, 0.444, 9.221)
            + struct.pack("<4f", 1.0, 69.09, 0.07, 5.1)
            + struct.pack("<4f", 0.04, 7.1, 3.9, 0.0)
            + struct.pack("<4f", 0.0, 0.0, 1.0, distance)
            + struct.pack("<4f", 0.0, 12.5, 2.0, 555.0)
        )
        return build_request_envelope(
            call_id=10,
            main_cmd=self.session.profile.fishing_main_cmd,
            sub_cmd=self.session.profile.fight_load_sub_cmd,
            payload=payload,
        )

    def test_glitch_distance_not_recorded(self) -> None:
        self.bridge._handle_client_frame(self.session, self._frame(-10.7))
        self.assertIsNone(self.session.fight_distance_by_gear.get(self.gear))

    def test_valid_distance_recorded(self) -> None:
        self.bridge._handle_client_frame(self.session, self._frame(26.2))
        self.assertAlmostEqual(self.session.fight_distance_by_gear.get(self.gear), 26.2, places=1)

    def test_glitch_keeps_last_valid(self) -> None:
        self.bridge._handle_client_frame(self.session, self._frame(26.2))
        self.bridge._handle_client_frame(self.session, self._frame(-10.7))
        self.assertAlmostEqual(self.session.fight_distance_by_gear.get(self.gear), 26.2, places=1)


if __name__ == "__main__":
    unittest.main()