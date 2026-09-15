"""rf4_core.bridge：搏鱼遥测格式化与分类测试。"""
from __future__ import annotations

import struct
import unittest
from unittest import mock

from rf4_core.bridge import FlowSession, RF4ChatBridge
from rf4_core.protocol import (
    FishSetupMeta,
    build_request_envelope,
    get_profile,
    pack_arg_header,
    pack_guid_marker,
    pack_marked_u32,
)


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

    def test_depth_from_position_report(self) -> None:
        # 位置上报浮点组(x, y, z)：y<0 为水下，深度取 abs(y)。
        groups = ((1.25, -8.5, 3.75),)
        self.assertEqual(self.bridge._fight_depth(groups), 8.5)

    def test_depth_above_water_returns_none(self) -> None:
        self.assertIsNone(self.bridge._fight_depth(((1.25, 2.5, 3.75),)))

    def test_depth_missing_position_group_returns_none(self) -> None:
        self.assertIsNone(self.bridge._fight_depth(((1.0, 2.0),)))


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

    def test_slim_line_includes_fish_info(self) -> None:
        from rf4_core.protocol import FishSetupMeta

        gear = "5a43c383-1111-1111-1111-111111111111"
        setup_id = "72121a20-1111-1111-1111-111111111111"
        self.session.fight_fish_by_gear[gear] = setup_id
        self.session.fish_setup_cache[setup_id] = FishSetupMeta(
            fish_setup_id=setup_id,
            fish_key="piksha",
            weight_hint_raw=444,
        )
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertIn("鱼=黑线鳕", text)
        self.assertIn("重量=444 克", text)

    def test_slim_line_shows_grade_when_known(self) -> None:
        from rf4_core.protocol import FishSetupMeta

        gear = "5a43c383-1111-1111-1111-111111111111"
        setup_id = "72121a20-1111-1111-1111-111111111111"
        self.session.fight_fish_by_gear[gear] = setup_id
        self.session.fish_setup_cache[setup_id] = FishSetupMeta(
            fish_setup_id=setup_id,
            fish_key="piksha",
            weight_hint_raw=444,
            setup_enum=2,
        )
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertIn("[达标]", text)
        self.assertIn("鱼=黑线鳕", text)

    def test_slim_line_omits_grade_when_unknown(self) -> None:
        from rf4_core.protocol import FishSetupMeta

        gear = "5a43c383-1111-1111-1111-111111111111"
        setup_id = "72121a20-1111-1111-1111-111111111111"
        self.session.fight_fish_by_gear[gear] = setup_id
        self.session.fish_setup_cache[setup_id] = FishSetupMeta(
            fish_setup_id=setup_id,
            fish_key="piksha",
            weight_hint_raw=444,
        )
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertNotIn("[达标]", text)
        self.assertNotIn("[不达标]", text)

    def test_slim_line_shows_rare_grades(self) -> None:
        from rf4_core.protocol import FishSetupMeta

        gear = "5a43c383-1111-1111-1111-111111111111"
        setup_id = "72121a20-1111-1111-1111-111111111111"
        self.session.fight_fish_by_gear[gear] = setup_id
        for enum, label in ((3, "稀有★"), (4, "超级稀有◆")):
            self.session.fish_setup_cache[setup_id] = FishSetupMeta(
                fish_setup_id=setup_id,
                fish_key="piksha",
                weight_hint_raw=444,
                setup_enum=enum,
            )
            text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
            self.assertIn(f"[{label}]", text)

    def test_slim_line_omits_fish_when_unknown(self) -> None:
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertNotIn("鱼=", text)

    def test_glitch_distance_keeps_last_value(self) -> None:
        self.session.fight_distance_by_gear["5a43c383-1111-1111-1111-111111111111"] = 26.2
        text = self.bridge._format_fight_load_payload(self.session, self._payload(-10.7))
        self.assertIn("出线 26.2米", text)

    def test_slim_line_includes_depth(self) -> None:
        gear = "5a43c383-1111-1111-1111-111111111111"
        self.session.fight_depth_by_gear[gear] = 4.5
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertIn("深4.5米", text)

    def test_slim_line_omits_depth_when_unknown(self) -> None:
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertNotIn("深", text)

    def test_handheld_gear_still_shows_fight_status(self) -> None:
        # 不挂槽位(从背包直接拿出的竿)没有竿号，但搏鱼状态不能丢：
        # 用"手持竿"前缀兜底，体力/出线照常显示。
        self.session.slot_items.clear()
        text = self.bridge._format_fight_load_payload(self.session, self._payload(26.2))
        self.assertIn("手持竿", text)
        self.assertIn("体力 100%", text)
        self.assertIn("出线 26.2米", text)


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
        self.assertEqual(self.session.rod_phase_by_gear.get(self.gear), "fighting")

    def test_glitch_keeps_last_valid(self) -> None:
        self.bridge._handle_client_frame(self.session, self._frame(26.2))
        self.bridge._handle_client_frame(self.session, self._frame(-10.7))
        self.assertAlmostEqual(self.session.fight_distance_by_gear.get(self.gear), 26.2, places=1)


class PositionReportDepthTests(unittest.TestCase):
    """14/7 位置上报：提取深度供搏鱼主行显示。"""

    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge

        self.gear = "5a43c383-1111-1111-1111-111111111111"
        self.pack_arg_header = pack_arg_header
        self.pack_guid_marker = pack_guid_marker
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        self.emitted: list[tuple[str, str]] = []
        self.bridge._log_telemetry = lambda cat, text: self.emitted.append((cat, text))

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _report(self, y: float, sub_cmd: int | None = None) -> bytes:
        payload = (
            self.pack_arg_header(b"507", 1)
            + self.pack_guid_marker(self.gear)
            + struct.pack("<fff", 123.0, y, 456.0)
        )
        return build_request_envelope(
            call_id=11,
            main_cmd=self.session.profile.fishing_main_cmd,
            sub_cmd=sub_cmd or self.session.profile.fight_step_sub_cmd,
            payload=payload,
        )

    def test_underwater_depth_recorded(self) -> None:
        self.bridge._handle_client_frame(self.session, self._report(-8.5))
        self.assertAlmostEqual(self.session.fight_depth_by_gear.get(self.gear), 8.5, places=2)

    def test_above_water_depth_not_recorded(self) -> None:
        self.bridge._handle_client_frame(self.session, self._report(2.5))
        self.assertIsNone(self.session.fight_depth_by_gear.get(self.gear))

    def test_new_cast_clears_stale_depth(self) -> None:
        self.session.fight_depth_by_gear[self.gear] = 8.5
        self.bridge._handle_client_frame(
            self.session,
            self._report(1.0, sub_cmd=self.session.profile.cast_prepare_sub_cmd),
        )
        self.assertIsNone(self.session.fight_depth_by_gear.get(self.gear))

    def test_waiting_depth_line_emitted_after_cast(self) -> None:
        # 抛竿后咬钩前位置上报就带深度，浮窗该竿应显示"已抛竿 深X.X米"。
        self.session.slot_items[3] = self.gear
        self.bridge._handle_client_frame(self.session, self._report(-1.53))
        self.assertEqual(
            self.emitted, [("fight_status", "3号杆 已抛竿 深1.5米")]
        )

    def test_waiting_depth_line_throttled_to_rounded_change(self) -> None:
        # 深度只有 1 位小数变化时才发新行，避免位置上报抖动刷屏。
        self.session.slot_items[3] = self.gear
        self.bridge._handle_client_frame(self.session, self._report(-1.53))
        self.bridge._handle_client_frame(self.session, self._report(-1.54))
        self.bridge._handle_client_frame(self.session, self._report(-1.72))
        self.assertEqual(
            self.emitted,
            [
                ("fight_status", "3号杆 已抛竿 深1.5米"),
                ("fight_status", "3号杆 已抛竿 深1.7米"),
            ],
        )

    def test_depth_line_suppressed_after_incoming(self) -> None:
        # 来鱼/咬钩期间深度行不得覆盖高优先级显示（否则看不出是脱钩还是咬钩）。
        self.session.slot_items[3] = self.gear
        self.session.rod_phase_by_gear[self.gear] = "incoming"
        self.bridge._handle_client_frame(self.session, self._report(-1.5))
        self.assertEqual(self.emitted, [])

    def test_depth_line_suppressed_during_result_hold(self) -> None:
        self.session.slot_items[3] = self.gear
        self.session.rod_phase_by_gear[self.gear] = "result"
        self.session.rod_result_until_by_gear[self.gear] = 10**12
        self.bridge._handle_client_frame(self.session, self._report(-1.5))
        self.assertEqual(self.emitted, [])

    def test_depth_line_resumes_after_result_hold_expires(self) -> None:
        self.session.slot_items[3] = self.gear
        self.session.rod_phase_by_gear[self.gear] = "result"
        self.session.rod_result_until_by_gear[self.gear] = 0.0
        self.bridge._handle_client_frame(self.session, self._report(-1.5))
        self.assertEqual(self.emitted, [("fight_status", "3号杆 已抛竿 深1.5米")])


class CastStageLineTests(unittest.TestCase):
    """抛竿阶段回显：浮窗搏鱼状态行显示"准备抛竿/已抛竿"，不再停留待机。"""

    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge

        self.gear = "5a43c383-1111-1111-1111-111111111111"
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        self.emitted: list[tuple[str, str]] = []
        self.bridge._log_telemetry = lambda cat, text: self.emitted.append((cat, text))

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _cast(self, sub_cmd: int) -> bytes:
        payload = pack_arg_header(b"507", 1) + pack_guid_marker(self.gear)
        return build_request_envelope(
            call_id=12,
            main_cmd=self.session.profile.fishing_main_cmd,
            sub_cmd=sub_cmd,
            payload=payload,
        )

    def test_prepare_emits_preparing_line(self) -> None:
        self.session.slot_items[1] = self.gear
        self.bridge._handle_client_frame(
            self.session, self._cast(self.session.profile.cast_prepare_sub_cmd)
        )
        self.assertEqual(self.emitted, [("fight_status", "1号杆 准备抛竿")])

    def test_cast_emits_cast_done_line(self) -> None:
        self.session.slot_items[2] = self.gear
        self.bridge._handle_client_frame(
            self.session, self._cast(self.session.profile.cast_sub_cmd)
        )
        self.assertEqual(self.emitted, [("fight_status", "2号杆 已抛竿")])
        self.assertEqual(self.session.rod_phase_by_gear.get(self.gear), "waiting")

    def test_handheld_gear_falls_back_to_label(self) -> None:
        self.bridge._handle_client_frame(
            self.session, self._cast(self.session.profile.cast_sub_cmd)
        )
        self.assertEqual(self.emitted, [("fight_status", "手持竿 已抛竿")])


class SelfEventLineTests(unittest.TestCase):
    """自我事件文本：鱼信息缺失时不能显示 "0 克" 这类误导数值。"""

    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import RF4ChatBridge

        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _event(self, phase: str, fish_key: str = "", weight_raw: int = 0) -> object:
        from rf4_core.bridge import SyntheticChatEvent

        return SyntheticChatEvent(
            event_id=1,
            fish_key=fish_key,
            weight_raw=weight_raw,
            location_id="",
            users_count=0,
            phase=phase,
            gear_slot_text="3号杆",
        )

    def test_bitten_without_fish_info_omits_weight(self) -> None:
        from rf4_core.bridge import RF4ChatBridge

        text = self.bridge._format_self_event_log_line(
            self._event(RF4ChatBridge.SELF_EVENT_PHASE_BITTEN)
        )
        self.assertEqual(text, "【我自己】：[3号杆] 咬钩了")
        self.assertNotIn("0", text.replace("3号杆", ""))

    def test_bitten_with_fish_info_keeps_details(self) -> None:
        from rf4_core.bridge import RF4ChatBridge

        text = self.bridge._format_self_event_log_line(
            self._event(RF4ChatBridge.SELF_EVENT_PHASE_BITTEN, "piksha", 444)
        )
        self.assertIn("黑线鳕", text)
        self.assertIn("444 克", text)
        self.assertTrue(text.endswith("咬钩了"))

    def test_kept_without_fish_info_omits_weight(self) -> None:
        from rf4_core.bridge import RF4ChatBridge

        text = self.bridge._format_self_event_log_line(
            self._event(RF4ChatBridge.SELF_EVENT_PHASE_KEPT)
        )
        self.assertEqual(text, "【我自己】：[3号杆] 有鱼入护了")


class RodPhaseTests(unittest.TestCase):
    """竿行显示阶段：来鱼/咬钩/搏鱼/结算期间深度行不得覆盖。"""

    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge

        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        self.gear = "5a43c383-1111-1111-1111-111111111111"

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _event(self, phase: str, gear: str | None = None) -> object:
        from rf4_core.bridge import SyntheticChatEvent

        return SyntheticChatEvent(
            event_id=1,
            fish_key="",
            weight_raw=0,
            location_id="",
            users_count=0,
            phase=phase,
            fishing_gear_id=self.gear if gear is None else gear,
        )

    def test_incoming_and_bitten_phases_recorded(self) -> None:
        from rf4_core.bridge import RF4ChatBridge

        self.bridge._set_rod_phase_for_event(
            self.session, self._event(RF4ChatBridge.SELF_EVENT_PHASE_INCOMING)
        )
        self.assertEqual(self.session.rod_phase_by_gear[self.gear], "incoming")
        self.bridge._set_rod_phase_for_event(
            self.session, self._event(RF4ChatBridge.SELF_EVENT_PHASE_BITTEN)
        )
        self.assertEqual(self.session.rod_phase_by_gear[self.gear], "bitten")

    def test_result_phase_sets_hold_deadline(self) -> None:
        from rf4_core.bridge import RF4ChatBridge

        self.bridge._set_rod_phase_for_event(
            self.session, self._event(RF4ChatBridge.SELF_EVENT_PHASE_KEPT)
        )
        self.assertEqual(self.session.rod_phase_by_gear[self.gear], "result")
        self.assertGreater(self.session.rod_result_until_by_gear[self.gear], 0.0)

    def test_event_without_gear_is_ignored(self) -> None:
        from rf4_core.bridge import RF4ChatBridge

        self.bridge._set_rod_phase_for_event(
            self.session, self._event(RF4ChatBridge.SELF_EVENT_PHASE_INCOMING, gear="")
        )
        self.assertEqual(len(self.session.rod_phase_by_gear), 0)


class SessionResetRowTests(unittest.TestCase):
    """会话开始补发等待竿行 / 会话结束清空通知（切服不丢行、小退不残留）。"""

    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge

        self.gear = "5a43c383-1111-1111-1111-111111111111"
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        self.session.slot_items[3] = self.gear
        self.emitted: list[tuple[str, str]] = []
        self.bridge._log_telemetry = lambda cat, text: self.emitted.append((cat, text))

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def test_reset_reemits_waiting_rod_rows(self) -> None:
        self.session.rod_phase_by_gear[self.gear] = "waiting"
        self.session.fight_depth_by_gear[self.gear] = 1.53
        with mock.patch.object(self.bridge, "_broadcast_generic_event") as reset_event:
            self.bridge.broadcast_reset(self.session)
        reset_event.assert_called_once_with("reset", "")
        self.assertEqual(self.emitted, [("fight_status", "3号杆 已抛竿 深1.5米")])

    def test_reset_skips_non_waiting_rods(self) -> None:
        self.session.rod_phase_by_gear[self.gear] = "fighting"
        self.session.fight_depth_by_gear[self.gear] = 1.53
        with mock.patch.object(self.bridge, "_broadcast_generic_event"):
            self.bridge.broadcast_reset(self.session)
        self.assertEqual(self.emitted, [])

    def test_session_end_writes_clear_event(self) -> None:
        with mock.patch.object(self.bridge, "_write_overlay_event") as write:
            self.bridge.broadcast_session_end()
        write.assert_called_once()
        event_name, payload = write.call_args[0][0], write.call_args[0][1]
        self.assertEqual(event_name, "session_end")
        self.assertIn("session_end", payload)


class FightStageInitialLineTests(unittest.TestCase):
    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge
        from rf4_core.protocol import FishSetupMeta

        self.pack_arg_header = pack_arg_header
        self.pack_guid_marker = pack_guid_marker
        self.gear = "5a43c383-1111-1111-1111-111111111111"
        self.setup_id = "72121a20-1111-1111-1111-111111111111"
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
                rf4_show_fish=True,
            rf4_avatar_url="",
            rf4_sender_level=1,
            rf4_sender_region="",
            rf4_sender_class="",
            rf4_sender_badge="",
            rf4_show_bitten=True,
        )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        self.session.slot_items[1] = self.gear
        self.session.fish_setup_cache[self.setup_id] = FishSetupMeta(
            fish_setup_id=self.setup_id,
            fish_key="piksha",
            weight_hint_raw=444,
        )

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _frame(self) -> bytes:
        payload = (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + self.pack_guid_marker(self.setup_id)
            + struct.pack("<4f", 34.16, 34.16, 0.195, 553.0)
        )
        return build_request_envelope(
            call_id=10,
            main_cmd=self.session.profile.fishing_main_cmd,
            sub_cmd=self.session.profile.fight_stage_sub_cmd,
            payload=payload,
        )

    def test_fight_stage_emits_initial_line_with_fish(self) -> None:
        frame = self._frame()
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, frame)
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fight_status")
        self.assertIn("1号杆", text)
        self.assertIn("鱼=黑线鳕", text)
        self.assertIn("重量=444 克", text)
        self.assertIn("体力 100%", text)

    def test_fight_stage_initial_line_shows_grade(self) -> None:
        from rf4_core.protocol import FishSetupMeta

        self.session.fish_setup_cache[self.setup_id] = FishSetupMeta(
            fish_setup_id=self.setup_id,
            fish_key="piksha",
            weight_hint_raw=444,
            setup_enum=2,
        )
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, self._frame())
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fight_status")
        self.assertIn("[达标]", text)
        self.assertIn("鱼=黑线鳕", text)

    def test_fight_stage_handheld_gear_still_emits(self) -> None:
        # 手持竿(不在快捷键槽位)也要有搏鱼初始行，体力/鱼名不能丢。
        self.session.slot_items.clear()
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, self._frame())
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fight_status")
        self.assertIn("手持竿", text)
        self.assertIn("鱼=黑线鳕", text)
        self.assertIn("体力 100%", text)


class FightTelemetryCategoryTests(unittest.TestCase):
    """三档拆分：搏鱼状态行 fight_status / 刷屏详情 fight_details / 其余鱼业务 fish。"""

    def setUp(self) -> None:
        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge
        from rf4_core.protocol import FishSetupMeta

        self.pack_arg_header = pack_arg_header
        self.pack_guid_marker = pack_guid_marker
        self.gear = "5a43c383-1111-1111-1111-111111111111"
        self.setup_id = "72121a20-1111-1111-1111-111111111111"
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
            )
        self.prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(options=options)
        self.bridge = RF4ChatBridge()
        self.session = FlowSession(profile=get_profile("4.0.24799"))
        self.session.slot_items[1] = self.gear
        self.session.fish_setup_cache[self.setup_id] = FishSetupMeta(
            fish_setup_id=self.setup_id,
            fish_key="piksha",
            weight_hint_raw=444,
        )

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _frame(self, sub_cmd: int, payload: bytes) -> bytes:
        return build_request_envelope(
            call_id=10,
            main_cmd=self.session.profile.fishing_main_cmd,
            sub_cmd=sub_cmd,
            payload=payload,
        )

    def _load_payload(self, distance: float) -> bytes:
        return (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + struct.pack("<4f", 2.0, 2.0, 0.444, 9.221)
            + struct.pack("<4f", 1.0, 69.09, 0.07, 5.1)
            + struct.pack("<4f", 0.04, 7.1, 3.9, 0.0)
            + struct.pack("<4f", 0.0, 0.0, 1.0, distance)
            + struct.pack("<4f", 0.0, 12.5, 2.0, 555.0)
        )

    def _stage_payload(self) -> bytes:
        return (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + self.pack_guid_marker(self.setup_id)
            + struct.pack("<4f", 34.16, 34.16, 0.195, 553.0)
        )

    def _step_payload(self) -> bytes:
        return (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + struct.pack("<4f", 4.169, -3.089, 795.774, 0.0)
            + struct.pack("<4f", 0.0, 0.126, 0.941, 0.95)
            + pack_marked_u32(292)
        )

    def _pull_payload(self) -> bytes:
        return (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + self.pack_guid_marker(self.setup_id)
            + pack_marked_u32(327)
        )

    def test_fight_load_goes_to_fight_status(self) -> None:
        frame = self._frame(self.session.profile.fight_load_sub_cmd, self._load_payload(26.2))
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, frame)
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fight_status")
        self.assertIn("1号杆", text)
        self.assertNotIn("浮点", text)

    def test_fight_stage_goes_to_fight_status(self) -> None:
        frame = self._frame(self.session.profile.fight_stage_sub_cmd, self._stage_payload())
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, frame)
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fight_status")

    def test_fight_step_goes_to_fight_details(self) -> None:
        frame = self._frame(self.session.profile.fight_step_sub_cmd, self._step_payload())
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, frame)
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fight_details")
        self.assertIn("位置上报", text)

    def test_fight_pull_goes_to_fight_details(self) -> None:
        frame = self._frame(self.session.profile.fight_pull_sub_cmd, self._pull_payload())
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, frame)
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fight_details")
        self.assertIn("拉线动作", text)

    def test_settlement_stays_fish(self) -> None:
        payload = (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + self.pack_guid_marker(self.setup_id)
            + pack_marked_u32(353)
        )
        frame = self._frame(self.session.profile.fight_pull_sub_cmd, payload)
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, frame)
        self.assertIsNotNone(telemetry)
        cat, _ = telemetry
        self.assertIn(cat, ("fight_details", "fish"))
