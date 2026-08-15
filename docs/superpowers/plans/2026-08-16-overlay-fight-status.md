# 浮窗搏鱼状态行（体力% + 出线米）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 浮窗在"遥测·钓鱼过程"勾选时，拉鱼期间显示精简的搏鱼状态行 `3号杆 | 体力 78% 出线 12.3米`，进入搏鱼即显示（带鱼名/重量），拉力帧刷新，多竿按 1/2/3 排序，入护/脱钩/放生后消失。

**Architecture:** bridge.py 在 fight_stage(14/11) 与 fight_load(14/8) 分支生成带竿号前缀的精简遥测行，经现有 `_broadcast_telemetry(category="fish")` 广播；rf4_overlay.pyw 解析 telemetry 文本中的竿号前缀，按竿号就地更新 `_rows`，并在 `_refresh_display` 按竿号数字排序输出。手持装备（无竿号）不广播。

**Tech Stack:** Python, tkinter overlay, UDP JSON 事件桥, unittest.

## Global Constraints

- 走现有"遥测·钓鱼过程"开关（`rf4_show_fish`），不新增配置项、不新增独立事件通道
- 单行紧凑格式：`{竿号} | 体力 {X}% 出线 {Y}米`
- 出线距离过滤：仅 `X > 0`（且非 NaN）才采用；负值/0 为搏鱼起始阶段瞬时抖动，保持上一帧值。出线**无上限**（40 米只是测试环境未超出的观测值）
- 体力字段：扫描浮点组第 2 组首位（`groups[1][0]`），校验 `0.05 <= v <= 1.05`，转百分比 `(v-0.1)/0.9*100` 并钳制 0~100
- 手持装备（`_gear_slot_text` 返回空）不显示搏鱼状态
- 进入搏鱼阶段(14/11)时输出初始行（体力 100%，含鱼名/重量），随后拉力帧(14/8)刷新
- 体力 ≤ 0 时浮窗行文字变红
- 多竿分行，`_refresh_display` 按竿号数字排序（1号杆 → 2号杆 → 3号杆）
- 不改动现有丢包恢复、RC4、握手等逻辑；现有 42 个测试保持通过

---

### Task 1: 新增体力提取与出线过滤辅助方法（bridge.py）

**Files:**
- Modify: `rf4_core/bridge.py:2608-2615`（`_fight_distance` 附近）
- Test: `tests/test_fish_setup.py`（新增测试类）

**Interfaces:**
- Consumes: 现有 `_scan_float_groups(payload, limit)` 返回 `Tuple[Tuple[float, ...], ...]`
- Produces:
  - `RF4ChatBridge._fight_stamina(groups) -> Optional[int]`：从 groups 第 2 组首位提体力百分比（0~100），越界返回 None
  - `RF4ChatBridge._is_valid_distance(value: float) -> bool`：`0 < value`（且非 NaN）
  - `RF4ChatBridge._sanitize_distance(value: Optional[float], last: Optional[float]) -> Optional[float]`：值合法则用之，否则用上一帧值

- [ ] **Step 1: 写失败测试**

在 `tests/test_fish_setup.py` 末尾（`FightPullAssociationTests` 之后、`if __name__` 之前）新增：

```python
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
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_fish_setup.py::FightStaminaHelpersTests -v`
Expected: FAIL（`AttributeError: 'RF4ChatBridge' object has no attribute '_fight_stamina'`）

- [ ] **Step 3: 实现辅助方法**

在 `rf4_core/bridge.py` 的 `_fight_distance`（:2609-2615）之后追加。同时修正 `_fight_distance` 注释中误导性的"出线上限"描述（出线无上限，40 只是测试环境观测值）：

```python
    @staticmethod
    def _fight_distance(groups: Tuple[Tuple[float, ...], ...]) -> Optional[float]:
        # 推断：搏鱼拉力消息中形如 (0, 0, 1, X) 的浮点组，X 为鱼到玩家的出线距离（米）。
        # 实测 67 条鱼 520 个采样，X 收竿时收敛到 ~2 米，故判定为距离而非体力。出线无上限。
        for group in groups:
            if len(group) >= 4 and abs(group[0]) < 0.001 and abs(group[1]) < 0.001 and abs(group[2] - 1.0) < 0.001:
                return group[3]
        return None

    @staticmethod
    def _fight_stamina(groups: Tuple[Tuple[float, ...], ...]) -> Optional[int]:
        # 实测确认：搏鱼拉力帧浮点组第 2 组首位为鱼体力(1.0 满, 0.1 力竭)。
        # 转百分比 (v-0.1)/0.9*100 并钳制 0~100；越界(非体力)返回 None。
        if len(groups) < 2 or not groups[1]:
            return None
        stamina = groups[1][0]
        if not (0.05 <= stamina <= 1.05):
            return None
        percent = (stamina - 0.1) / 0.9 * 100
        return int(max(0, min(100, round(percent))))

    @staticmethod
    def _is_valid_distance(value: float) -> bool:
        # 出线无上限；0/负值为搏鱼起始阶段的瞬时抖动，NaN 为解析失败，应过滤。
        return not (value != value) and value > 0

    @staticmethod
    def _sanitize_distance(value: Optional[float], last: Optional[float]) -> Optional[float]:
        if value is not None and RF4ChatBridge._is_valid_distance(value):
            return value
        return last
```

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_fish_setup.py::FightStaminaHelpersTests -v`
Expected: PASS（7 passed）

- [ ] **Step 5: 提交**

```bash
git add rf4_core/bridge.py tests/test_fish_setup.py
git commit -m "feat: add fight stamina extraction and distance sanitizing helpers"
```

---

### Task 2: 精简 `_format_fight_load_payload` 并过滤异常帧（bridge.py）

**Files:**
- Modify: `rf4_core/bridge.py:2379-2410`（`_format_fight_load_payload`）
- Test: `tests/test_fish_setup.py`

**Interfaces:**
- Consumes: `_fight_stamina`、`_is_valid_distance`、`_sanitize_distance`（Task 1）、`_gear_slot_text`、`_fight_distance`、`_fish_meta_for_gear`
- Produces: 精简后的 `_format_fight_load_payload(session, payload) -> str`，输出 `3号杆 | 体力 78% 出线 12.3米`（无浮点组/拉力方向/负载/序号）

- [ ] **Step 1: 写失败测试**

在 `tests/test_fish_setup.py` 的 `FightStaminaHelpersTests` 之后新增：

```python
class FightLoadSlimLineTests(unittest.TestCase):
    def setUp(self) -> None:
        from types import SimpleNamespace

        import struct

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge
        from rf4_core.protocol import FishSetupMeta, get_profile, pack_arg_header, pack_guid_marker

        self.struct = struct
        self.pack_arg_header = pack_arg_header
        self.pack_guid_marker = pack_guid_marker
        self.FishSetupMeta = FishSetupMeta
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
            + self.struct.pack("<4f", 2.0, 2.0, 0.444, 9.221)
            + self.struct.pack("<4f", stamina, 69.09, 0.07, 5.1)
            + self.struct.pack("<4f", 0.04, 7.1, 3.9, 0.0)
            + self.struct.pack("<4f", 0.0, 0.0, 1.0, distance)
            + self.struct.pack("<4f", 0.0, 12.5, 2.0, 555.0)
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
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_fish_setup.py::FightLoadSlimLineTests -v`
Expected: FAIL（当前输出含浮点组/拉力方向，且无"1号杆"前缀）

- [ ] **Step 3: 实现精简逻辑**

替换 `_format_fight_load_payload` 函数体（:2379-2410）：

```python
    def _format_fight_load_payload(self, session: FlowSession, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        gear = self._first_guid(summary)
        if not gear:
            return ""
        gear_slot = self._gear_slot_text(session, gear)
        if not gear_slot:
            # 手持装备(不在快捷键槽位)不显示搏鱼状态。
            return ""
        groups = self._scan_float_groups(payload, limit=8)
        stamina = self._fight_stamina(groups)
        distance = self._sanitize_distance(
            self._fight_distance(groups),
            session.fight_distance_by_gear.get(gear),
        )
        parts = [gear_slot]
        if stamina is not None:
            parts.append(f"体力 {stamina}%")
        if distance is not None:
            parts.append(f"出线 {self._format_float(distance)}米")
        return " | ".join(parts)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_fish_setup.py::FightLoadSlimLineTests -v`
Expected: PASS（3 passed）

- [ ] **Step 4b: 让遥测输出行不带标签前缀（适配浮窗竿号前缀匹配）**

`_describe_known_client_business_telemetry` 的 fight_load 分支（:1556-1557）当前把 `_format_fight_load_payload` 结果包进 `_format_business_line(label, details)`，输出 `搏鱼拉力 | 1号杆 | ...`。浮窗按 `^(\d+)号杆 ` 前缀识别，需让广播 text 直接以竿号开头。

将 `rf4_core/bridge.py:1554-1566` 的 fight_load 分支改为直接返回精简行（不带标签前缀）：

```python
        if sub_cmd == profile.fight_step_sub_cmd:
            details = self._format_fish_move_payload(envelope.payload)
        elif sub_cmd == profile.fight_load_sub_cmd:
            slim = self._format_fight_load_payload(session, envelope.payload)
            if slim:
                return "fish", slim
            return None
        elif sub_cmd == profile.fight_pull_sub_cmd:
            details = self._format_fight_pull_payload(session, envelope.payload)
        elif sub_cmd == profile.fight_stage_sub_cmd:
            details = self._format_fight_stage_payload(envelope.payload)
        elif sub_cmd == profile.contact_left_sub_cmd:
            details = self._format_contact_left_payload(envelope.payload)
        else:
            details = self._format_generic_business_payload(envelope.payload)
        return "fish", self._format_business_line(label, details)
```

- [ ] **Step 4c: 运行测试确认仍通过**

Run: `py -m pytest tests/test_fish_setup.py -v`
Expected: PASS（原有 + 本计划 FightLoadSlimLineTests 全通过）

- [ ] **Step 5: 提交**

```bash
git add rf4_core/bridge.py tests/test_fish_setup.py
git commit -m "feat: slim fight-load telemetry line, filter glitch distance frames"
```

---

### Task 3: fight_load 分支记录过滤后的出线（bridge.py）

**Files:**
- Modify: `rf4_core/bridge.py:2832-2845`（`_handle_client_frame` 的 fight_load 分支）
- Test: `tests/test_fish_setup.py`

**Interfaces:**
- Consumes: `_sanitize_distance`（Task 1）
- Produces: `session.fight_distance_by_gear` 只存过滤后的合法值（供 `_format_fight_load_payload` 的上一帧回退使用）

**注意**：fight_load 的遥测行已由 `_describe_known_client_business_telemetry`（`_maybe_log_telemetry_frame` 先于 `_handle_client_frame` 调用，见 bridge.py:1287/1298）通过 `_format_fight_load_payload` 发出。**不要**在 `_handle_client_frame` 再调 `_log_telemetry`，否则重复广播。本任务只改距离记录逻辑。

- [ ] **Step 1: 写失败测试**

在 `tests/test_fish_setup.py` 新增：

```python
class FightLoadRecordDistanceTests(unittest.TestCase):
    def setUp(self) -> None:
        import struct

        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge
        from rf4_core.protocol import get_profile, pack_arg_header, pack_guid_marker

        self.struct = struct
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
        from rf4_core.protocol import build_request_envelope

        payload = (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + self.struct.pack("<4f", 2.0, 2.0, 0.444, 9.221)
            + self.struct.pack("<4f", 1.0, 69.09, 0.07, 5.1)
            + self.struct.pack("<4f", 0.04, 7.1, 3.9, 0.0)
            + self.struct.pack("<4f", 0.0, 0.0, 1.0, distance)
            + self.struct.pack("<4f", 0.0, 12.5, 2.0, 555.0)
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
        self.assertEqual(self.session.fight_distance_by_gear.get(self.gear), 26.2)

    def test_glitch_keeps_last_valid(self) -> None:
        self.bridge._handle_client_frame(self.session, self._frame(26.2))
        self.bridge._handle_client_frame(self.session, self._frame(-10.7))
        self.assertEqual(self.session.fight_distance_by_gear.get(self.gear), 26.2)
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_fish_setup.py::FightLoadRecordDistanceTests -v`
Expected: FAIL（当前分支直接存原始 distance，负值会被记录）

- [ ] **Step 3: 实现过滤记录**

修改 `_handle_client_frame` 的 fight_load 分支（:2832-2845）中的距离记录：

```python
        # 搏鱼拉力(14/8)：记录该钓组当前出线距离(过滤瞬时负值/超限)，供拉线动作/搏鱼关联展示。
        fight_load = parse_fishing_gear_and_setup(envelope, session.profile, session.profile.fight_load_sub_cmd)
        if fight_load and fight_load.fishing_gear_id:
            groups = self._scan_float_groups(envelope.payload, limit=8)
            distance = self._sanitize_distance(
                self._fight_distance(groups),
                session.fight_distance_by_gear.get(fight_load.fishing_gear_id),
            )
            if distance is not None:
                session.fight_distance_by_gear[fight_load.fishing_gear_id] = distance
            if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                self._log(
                    f"fight_load 钓组={self._short_id(fight_load.fishing_gear_id)} "
                    f"出线={self._format_float(distance) if distance is not None else '?'}米 "
                    f"hex={self._hex_preview(envelope.payload, limit=160)}"
                )
            return plain_body, []
```

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_fish_setup.py::FightLoadRecordDistanceTests -v`
Expected: PASS（3 passed）

- [ ] **Step 5: 提交**

```bash
git add rf4_core/bridge.py tests/test_fish_setup.py
git commit -m "feat: record only sanitized fight distance per gear"
```

---

### Task 4: fight_stage(14/11) 输出初始体力行（含鱼名/重量）（bridge.py）

**Files:**
- Modify: `rf4_core/bridge.py:1560-1561`（`_describe_known_client_business_telemetry` 的 fight_stage 分支，替换冗长行）
- Test: `tests/test_fish_setup.py`

**Interfaces:**
- Consumes: `_gear_slot_text`、`_format_fish_name`、`_format_chat_weight`、`_scan_float_groups`、`parse_fishing_gear_and_setup`
- Produces: fight_stage 帧 → 广播初始行 `1号杆 | 鱼=黑线鳕 重量=444克 体力 100% 出线 34.1米`（**替换**现冗长 `进入搏鱼阶段 | 状态值=(...)` 行）

**关键时序**：`_maybe_log_telemetry_frame`（:1287）先于 `_handle_client_frame`（:1298）运行，故描述路径拿不到 `session.fight_fish_by_gear`（在 :2852 才写入）。改用帧内自身携带的 `fight_stage.fish_setup_id` 查 `session.fish_setup_cache`。`_handle_client_frame` 的 fight_stage 分支（:2847-2868）**保持不动**（继续触发 BITTEN 事件 + 写 `fight_fish_by_gear`），不再二次 emit。

- [ ] **Step 1: 写失败测试**

在 `tests/test_fish_setup.py` 新增：

```python
class FightStageInitialLineTests(unittest.TestCase):
    def setUp(self) -> None:
        import struct

        from types import SimpleNamespace

        from rf4_core import bridge as bridge_mod
        from rf4_core.bridge import FlowSession, RF4ChatBridge
        from rf4_core.protocol import FishSetupMeta, get_profile, pack_arg_header, pack_guid_marker

        self.struct = struct
        self.pack_arg_header = pack_arg_header
        self.pack_guid_marker = pack_guid_marker
        self.FishSetupMeta = FishSetupMeta
        self.gear = "5a43c383-1111-1111-1111-111111111111"
        self.setup_id = "72121a20-1111-1111-1111-111111111111"
        options = SimpleNamespace(
            rf4_verbose_logging=False,
            rf4_log_telemetry=True,
            rf4_telemetry_categories="all",
            rf4_event_bridge_port=0,
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
        self.emitted: list[tuple[str, str]] = []
        self.bridge._log_telemetry = lambda cat, text: self.emitted.append((cat, text))

    def tearDown(self) -> None:
        import rf4_core.bridge as bridge_mod

        bridge_mod.ctx = self.prev_ctx

    def _frame(self) -> bytes:
        from rf4_core.protocol import build_request_envelope

        payload = (
            self.pack_arg_header(b"507", 3)
            + self.pack_guid_marker(self.gear)
            + self.pack_guid_marker(self.setup_id)
            + self.struct.pack("<4f", 34.16, 34.16, 0.195, 553.0)
        )
        return build_request_envelope(
            call_id=10,
            main_cmd=self.session.profile.fishing_main_cmd,
            sub_cmd=self.session.profile.fight_stage_sub_cmd,
            payload=payload,
        )

    def test_fight_stage_emits_initial_line_with_fish(self) -> None:
        from rf4_core.protocol import parse_envelope

        frame = self._frame()
        envelope = parse_envelope(frame)
        telemetry = self.bridge._describe_telemetry_frame(self.session, True, frame)
        self.assertIsNotNone(telemetry)
        cat, text = telemetry
        self.assertEqual(cat, "fish")
        self.assertIn("1号杆", text)
        self.assertIn("鱼=黑线鳕", text)
        self.assertIn("重量=444克", text)
        self.assertIn("体力 100%", text)
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_fish_setup.py::FightStageInitialLineTests -v`
Expected: FAIL（当前 fight_stage 描述行是 `进入搏鱼阶段 | 状态值=(...)`，无 `1号杆`/`体力 100%`）

- [ ] **Step 3: 实现初始行输出（替换冗长行）**

将 `_describe_known_client_business_telemetry` 的 fight_stage 分支（:1560-1561）改为：

```python
        elif sub_cmd == profile.fight_stage_sub_cmd:
            slim = self._format_fight_stage_initial_line(session, envelope)
            if slim:
                return "fish", slim
            return None
```

并在 `_format_fight_stage_payload` 之后新增静态辅助方法：

```python
    def _format_fight_stage_initial_line(self, session: FlowSession, envelope: RpcEnvelope) -> Optional[str]:
        """进入搏鱼阶段(14/11)的初始浮窗行：竿号 + 鱼名/重量 + 体力 100% + 初始出线。"""
        fight_stage = parse_fishing_gear_and_setup(
            envelope, session.profile, session.profile.fight_stage_sub_cmd
        )
        if not fight_stage or not fight_stage.fishing_gear_id:
            return None
        gear_slot = self._gear_slot_text(session, fight_stage.fishing_gear_id)
        if not gear_slot:
            return None
        meta = session.fish_setup_cache.get(fight_stage.fish_setup_id or "") if fight_stage.fish_setup_id else None
        fish_name = self._format_fish_name(meta.fish_key or "") if meta else ""
        weight = self._format_chat_weight(meta.weight_hint_raw) if meta and meta.weight_hint_raw else ""
        initial_distance = None
        for group in self._scan_float_groups(envelope.payload, limit=8):
            if group and self._is_valid_distance(group[0]):
                initial_distance = group[0]
                break
        parts = [gear_slot]
        if fish_name:
            parts.append(f"鱼={fish_name}")
        if weight:
            parts.append(f"重量={weight}")
        parts.append("体力 100%")
        if initial_distance is not None:
            parts.append(f"出线 {self._format_float(initial_distance)}米")
        return " | ".join(parts)
```

**注意**：`parse_fishing_gear_and_setup`（protocol.py:1275）接收 **envelope**（非裸 payload），故本辅助方法入参为 `envelope`；`_scan_float_groups` 用 `envelope.payload`。

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_fish_setup.py::FightStageInitialLineTests -v`
Expected: PASS（1 passed）

- [ ] **Step 5: 全量回归**

Run: `py -m pytest -v`
Expected: PASS（原有 42 + 本计划新增全通过）

- [ ] **Step 6: 提交**

```bash
git add rf4_core/bridge.py tests/test_fish_setup.py
git commit -m "feat: emit slim initial fight line with fish info on fight-stage"
```

---

### Task 5: 浮窗按竿号就地更新并排序（rf4_overlay.pyw）

**Files:**
- Modify: `rf4_overlay.pyw:352-371`（`_handle_datagram` 的 telemetry 分支）
- Modify: `rf4_overlay.pyw:264-278`（`_refresh_display` 排序输出）
- Test: `tests/test_overlay.py`

**Interfaces:**
- Consumes: telemetry 事件 text（含 `{竿号} | ...` 前缀，竿号形如 `1号杆`）
- Produces:
  - 命中竿号前缀的 telemetry → `_update_row(竿号, text)` 就地更新
  - 未命中 → 现有 `_show_generic(text)`（追加区）
  - `_refresh_display` 按竿号数字排序输出 `_rows`
  - `_rod_sort_key(slot: str) -> tuple`：`("1号杆",) → (1,)`，非竿号 → 排最后

- [ ] **Step 1: 写失败测试**

在 `tests/test_overlay.py` 新增：

```python
class OverlayFightStatusTests(unittest.TestCase):
    def _overlay(self) -> Overlay:
        ov = object.__new__(Overlay)
        ov._rows = {}
        ov._telemetry_rows = {}
        ov._telemetry_seq = 0
        ov._update_row = Overlay._update_row.__get__(ov)
        ov._refresh_display = lambda: None
        return ov

    def test_rod_prefixed_telemetry_updates_row_in_place(self) -> None:
        ov = self._overlay()
        payload = json.dumps(
            {"event": "telemetry", "category": "fish", "text": "3号杆 | 体力 78% 出线 12.3米"},
            ensure_ascii=False,
        )
        ov._handle_datagram(payload.encode("utf-8"))
        self.assertEqual(ov._rows.get("3号杆"), "3号杆 | 体力 78% 出线 12.3米")

    def test_plain_telemetry_goes_to_generic(self) -> None:
        ov = self._overlay()
        ov._show_generic = lambda text: ov._rows.__setitem__("generic", text)
        ov._handle_datagram(b'{"event":"telemetry","category":"player","text":"x=1"}')
        self.assertEqual(ov._rows.get("generic"), "x=1")
        self.assertNotIn("3号杆", ov._rows)

    def test_rod_sort_order(self) -> None:
        ov = object.__new__(Overlay)
        ov._rows = {"3号杆": "c", "1号杆": "a", "2号杆": "b"}
        keys = sorted(ov._rows, key=Overlay._rod_sort_key)
        self.assertEqual(keys, ["1号杆", "2号杆", "3号杆"])
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_overlay.py::OverlayFightStatusTests -v`
Expected: FAIL（telemetry 仍进追加区，无 `_rod_sort_key`）

- [ ] **Step 3: 实现浮窗逻辑**

(a) `rf4_overlay.pyw` 顶部确认 `import re`（若缺则添加）。

(b) 新增排序辅助方法（放在 `_clear_row` 之后）：

```python
    @staticmethod
    def _rod_sort_key(slot: str) -> tuple:
        # 竿号按数字排序(1号杆→2号杆→3号杆)；非竿号行排最后。
        match = re.match(r"^(\d+)号杆$", slot or "")
        if match:
            return (0, int(match.group(1)))
        return (1, 0)
```

(c) 修改 `_refresh_display`（:266）：

```python
        lines = [self._rows[key] for key in sorted(self._rows, key=self._rod_sort_key)]
```

(d) 修改 `_handle_datagram` 的 telemetry 分支（:367-369）：

```python
        elif name == "telemetry":
            if not text:
                return
            match = re.match(r"^(\d+)号杆 ", text)
            if match:
                self._update_row(f"{match.group(1)}号杆", text)
            else:
                self._show_generic(text)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_overlay.py -v`
Expected: PASS（原有 7 + 新增 3 = 10 passed）

- [ ] **Step 5: 提交**

```bash
git add rf4_overlay.pyw tests/test_overlay.py
git commit -m "feat: overlay updates fight rows in place and sorts by rod number"
```

---

### Task 6: 体力 ≤ 0 行变红（rf4_overlay.pyw）

**Files:**
- Modify: `rf4_overlay.pyw:264-278`（`_refresh_display` 着色）
- Test: `tests/test_overlay.py`

**Interfaces:**
- Consumes: 搏鱼行文本 `{竿号} | 体力 {X}% 出线 {Y}米`
- Produces: `_refresh_display` 中体力 ≤ 0 的行文字变红（#ff5252），其余用样式前景色

- [ ] **Step 1: 写失败测试**

在 `tests/test_overlay.py` 新增：

```python
class OverlayFightColorTests(unittest.TestCase):
    def test_exhausted_fight_row_is_red(self) -> None:
        ov = object.__new__(Overlay)
        row = "1号杆 | 体力 0% 出线 2.1米"
        self.assertEqual(Overlay._fight_row_color(row, "#ffd166"), "#ff5252")

    def test_active_fight_row_uses_default_color(self) -> None:
        ov = object.__new__(Overlay)
        row = "1号杆 | 体力 78% 出线 12.3米"
        self.assertEqual(Overlay._fight_row_color(row, "#ffd166"), "#ffd166")
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_overlay.py::OverlayFightColorTests -v`
Expected: FAIL（`AttributeError: 'Overlay' object has no attribute '_fight_row_color'`）

- [ ] **Step 3: 实现着色辅助方法**

在 `rf4_overlay.pyw` 的 `_rod_sort_key` 之后新增：

```python
    @staticmethod
    def _fight_row_color(text: str, default: str) -> str:
        # 体力 ≤ 0 表示鱼已力竭，行文字变红；其余用默认前景色。
        match = re.search(r"体力\s*(\d+)%", text)
        if match and int(match.group(1)) <= 0:
            return "#ff5252"
        return default
```

- [ ] **Step 4: 修改 `_refresh_display` 应用着色**

`self.label` 是单 Label，无法按行分别着色。沿用 `_show_anticheat` 的整窗变色模式：`_refresh_display` 末尾扫描全部行，若任一搏鱼行体力 ≤ 0，则 `self.label.config(fg="#ff5252")`；否则恢复样式前景色（`apply_style` 已含恢复逻辑，这里用 `self._STYLE_PARAMS[self.style]["fg"]` 恢复）。

在 `_refresh_display`（:271-272 `self.label.config(text=display)` 之后）追加：

```python
        exhausted = any(
            Overlay._fight_row_color(text, self._STYLE_PARAMS[self.style]["fg"]) == "#ff5252"
            for text in lines
        )
        self.label.config(
            fg="#ff5252" if exhausted else self._STYLE_PARAMS[self.style]["fg"]
        )
```

力竭时整窗变红提示明显（与 `_show_anticheat` 同模式），多竿不同色冲突在单 Label 下无法避免，属可接受限制。

- [ ] **Step 5: 运行测试确认通过**

Run: `py -m pytest tests/test_overlay.py -v`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add rf4_overlay.pyw tests/test_overlay.py
git commit -m "feat: tint overlay red when fight stamina reaches zero"
```

---

### Task 7: 回归测试与收尾

**Files:**
- Test: `tests/test_fish_setup.py`, `tests/test_overlay.py`, `tests/test_gear_slot.py`, `tests/test_recover_gap.py`, `tests/test_config_cache.py`

- [ ] **Step 1: 运行全部测试**

Run: `py -m pytest tests -v`
Expected: 全部通过（原 42 + 本计划新增，约 55+）

- [ ] **Step 2: 手工冒烟**

用 `logs/rf4_sniffer.log` 中真实 fight_load/fight_stage 结构验证 `_format_fight_load_payload` 输出符合预期（可选）。

- [ ] **Step 3: 检查 git 状态干净**

Run: `git status --short`
Expected: 无未提交改动（本计划各任务已逐个提交）

---

## Self-Review Notes

- 规格覆盖：需求(精简行/进入即显示/结束消失/过滤异常/多竿排序/手持不显示/走遥测开关) → Task 1-6 全覆盖
- Task 6 明确记录单 Label 着色限制（力竭时整窗变红），与规格"体力≤0行变红"的意图一致（提示明显）
- 类型一致性：`_fight_stamina`→`_fight_distance`→`_sanitize_distance`→`_is_valid_distance` 命名在 Task 1-3 间一致；`_rod_sort_key`/`_fight_row_color` 在 Task 5-6 间一致
- 测试 payload 布局已用探针验证（arg_header + gear_guid + 5 组浮点 → groups[1][0]=体力, groups[3][3]=出线）