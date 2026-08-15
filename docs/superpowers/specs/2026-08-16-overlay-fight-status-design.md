# 浮窗搏鱼状态行（体力% + 出线米）设计

日期：2026-08-16

## 背景与目标

RF4 Monitor 已确认搏鱼拉力消息(14/8)中：
- 扫描浮点组第 2 组首位 = **鱼体力**（1.0=100%，转百分比 `(v-0.1)/0.9*100`，越界钳制）
- 第 4 组 `(0,0,1,X)` 的 X = **出线距离（米）**

目前搏鱼拉力信息走 `_broadcast_telemetry`（category=fish），受显示设置"遥测·钓鱼过程"勾选控制。用户未勾选该选项，但希望拉鱼时在浮窗上**同步显示体力与出线**，仿 RF4-Tools 作者的做法（搏鱼状态作为独立事件输出，HUD 端实时刷新该竿行）。

## 需求

- 拉鱼时浮窗实时显示当前竿的 **体力% + 出线米**
- 单行紧凑：`3号杆 | 体力 78% 出线 12.3米`
- 不受"遥测·钓鱼过程"开关影响（独立事件通道）
- 搏鱼结束（入护/脱钩/放生）后该行消失
- 体力 ≤ 0 时行变红（仿作者 HUD 警告）

## 设计

### 1. bridge.py：`_handle_client_frame` 的 fight_load 分支

现有处理点 `rf4_core/bridge.py:2833` 已解析 fight_load 并记录出线距离。在该分支追加：

- 提取体力：从 `_scan_float_groups` 结果中取第 2 组（`groups[1]`）的首位，校验 `0.05 <= v <= 1.05` 后转为百分比
- 复用现有 `_fight_distance(groups)` 得出线
- 新增独立广播 `fight_status` 事件，**不经过 `_broadcast_telemetry` 的开关过滤**，仅受 UDP 桥端口（`rf4_event_bridge_port > 0`）控制

事件格式：

```json
{
  "event": "fight_status",
  "gear_slot": "3号杆",
  "stamina": 78,
  "distance": 12.3
}
```

- `gear_slot` 用现有 `_gear_slot_text(session, fishing_gear_id)` 得到
- 每个 fight_load 帧都广播（浮窗就地刷新，无刷屏问题，无需作者式的 5% 去重）

### 2. rf4_overlay.pyw：新增 `fight_status` 处理

- 收到 `fight_status` → 就地更新 `self._rows[gear_slot]` 为 `{gear_slot} | 体力 {stamina}% 出线 {distance}米`
- 体力 ≤ 0 → 行文字变红（记录红/常规色，便于结束时恢复）
- 收到 `fish_kept`/`fish_escaped`/`fish_released`（同 gear_slot）→ 清除该行（这些事件已有 clear_after=3000 机制）

### 3. 开关与默认

- 不新增配置项。fight_status 广播跟随 `rf4_event_bridge_port`（与来鱼/咬钩事件一致），与遥测勾选无关。

## 测试

- bridge 测试：构造 fight_load 帧，断言 `_handle_client_frame` 触发 fight_status 广播（含 stamina/distance 正确换算）
- overlay 测试：投递 fight_status datagram，断言该竿行文本正确；投递 fish_kept 后行消失
- 回归：现有 42 个测试保持通过

## 风险

- 体力字段（groups[1][0]）是推断，已验证 67 条鱼、553 帧，无 0.05~1.05 越界误判
- fight_load 频率约 2s/次，UDP 广播量可控