# 搏鱼遥测三档显示拆分设计

日期：2026-08-16

## 背景

用户反馈：开启"搏鱼过程"（`telemetry_fish`）后，浮窗/日志出现大量无关信息行（位置上报、拉线动作、钓组、坐标、浮点等），而用户只想单独看到**搏鱼状态行**（`1号杆 | 体力 100% 出线 33.486米`）。现有 `telemetry_fish` 一个开关打包了所有 `fish` 类别遥测，粒度太粗。

用户要求：像来鱼/咬钩/脱钩/入户/放生那样**细化显示开关**，搏鱼状态行能单独一行显示、独立开关控制。

## 需求（已确认，三档拆分）

将原泛化 `fish` 遥测类别拆成三档，各自独立开关：

| 档位 | 内容 | 配置键 | option 名 | 默认 |
|---|---|---|---|---|
| **fight_status** | 搏鱼状态行（体力% + 出线米），含进入搏鱼初始行 | `fight_status` | `rf4_show_fight_status` | 开 |
| **fight_details** | 位置上报/拉线动作/接触脱离等刷屏过程详情 | `fight_details` | `rf4_show_fight_details` | 关 |
| **fish**（保留） | 结算/入护/有鱼靠近等低频业务行 | `telemetry_fish` | `rf4_show_fish` | 关 |

## 设计

### 1. bridge.py：`_describe_known_client_business_telemetry` 类别拆分

`rf4_core/bridge.py` 钓鱼命令分支现统一返回 `("fish", ...)`。改为：

- `fight_load_sub_cmd`（搏鱼拉力）→ `("fight_status", slim)`（精简行不变）
- `fight_stage_sub_cmd`（进入搏鱼）→ `("fight_status", slim)`（初始行不变）
- `fight_step_sub_cmd`（位置上报）→ `("fight_details", 行)`
- `fight_pull_sub_cmd`（拉线动作）→ `("fight_details", 行)`
- `contact_left_sub_cmd`（接触/脱离）→ `("fight_details", 行)`
- 其余钓鱼业务（抛竿/结算/入护等）→ 保持 `("fish", 行)`

### 2. bridge.py：开关映射

`_telemetry_show_option` 新增：
- `"fight_status" -> "rf4_show_fight_status"`
- `"fight_details" -> "rf4_show_fight_details"`

`_option_name_to_key` 新增（托盘配置短键）：
- `"rf4_show_fight_status" -> "fight_status"`
- `"rf4_show_fight_details" -> "fight_details"`

`_register_options` 新增两个布尔开关。

### 3. rf4_tray.py：托盘菜单

`SHOW_ITEMS` 在 `telemetry_fish` 后新增：
- `("fight_status", "搏鱼状态行", "rf4_show_fight_status")`
- `("fight_details", "遥测·搏鱼过程(位置/拉线)", "rf4_show_fight_details")`

### 4. rf4_show_config.json

新增 `"fight_status": true`、`"fight_details": false`。

### 5. rf4_overlay.pyw

无需改动：搏鱼状态行带 `X号杆 | ` 前缀，走现有 `telemetry` 事件的号杆前缀就地更新逻辑；`fight_details` 行无号杆前缀，按普通遥测进通用区。

### 6. 日志

沿用现有 telemetry 日志输出（`_telemetry_enabled` 默认 `all`，新类别自动放行），搏鱼状态行仍为单行。

## 测试

- bridge：fight_load/fight_stage → `fight_status` 类别
- bridge：fight_step/fight_pull → `fight_details` 类别
- bridge：结算/入护 → 仍 `fish` 类别
- 映射：`_telemetry_show_option` / `_option_name_to_key` 新键
- overlay：`fight_status` 类别带号杆前缀 → 就地更新行；`fight_details` → 通用区

## 风险

- `fight_details` 行内容仍带 `钓组=...` 详情，若用户开此档仍会看到原始字段，属预期（该档即原始过程详情）。
- 日志全量输出不受开关影响，用户若嫌日志刷屏可另用 `rf4_telemetry_categories` 过滤。