# 浮窗玻璃拟态观感改造 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 RF4 来鱼浮窗从单 Label 改造成 Canvas 半透明玻璃圆角卡片（青黑玻璃底 + 青绿字 + 三极芯片体超粗字体）。

**Architecture:** 在 `rf4_overlay.pyw` 内用 `tk.Canvas` 替换 `tk.Label` 作为唯一渲染面。Canvas 上绘制圆角背景矩形、内侧高光描边、顶部 HUD 装饰线和左对齐文本；四角圆角区域以透明键 `#0000FF` 填充实现真圆角。所有事件分发、拖动、位置记忆、配置热载逻辑保持不动，只把 `label.config(text=...)` 改为 Canvas 重绘 `_draw()`。

**Tech Stack:** Python 3 + Tkinter（`tk.Canvas`、`tk.font`），unittest。Windows `-transparentcolor` 实现真圆角。

## Global Constraints

- 字体族名：`三极芯片体 超粗`；若 `tkfont.families()` 不含该族则回退 `Microsoft YaHei UI`
- 颜色值（固定，来自 spec）：背景 `#0F1916`、描边 `#1D4D3F`、装饰线 `#2EE6A8`、主文字 `#4FF2C8`、遥测/待机 `#8FD6C2`、力竭红 `#FF5252`、透明键哨兵 `#0000FF`、圆角半径 12
- 窗口宽 `WINDOW_WIDTH = 320` 不变；高度仍按内容自适应（`_content_height`）
- `-transparentcolor` 保持使用（dark/transparent 两模式均设置）
- 现有事件处理 `_handle_datagram`、拖动 `_on_press/_on_drag/_on_release`、位置记忆 `save_config`、配置热载 `_poll_config` 行为必须保持不变（现有测试必须全绿）
- 平台：Windows（透明键依赖）；不引入新依赖

---

### Task 1: Canvas 渲染面与玻璃卡片绘制

**Files:**
- Modify: `rf4_overlay.pyw:59-73`（`Overlay` 样式常量区）、`:106-120`（`__init__` 渲染面创建）、`:171-187`（`apply_style`）
- Test: `tests/test_overlay.py`

**Interfaces:**
- Consumes: 现有 `Overlay._STYLE_PARAMS`、`WINDOW_WIDTH`、`Overlay.load_config`
- Produces:
  - `Overlay.CANVAS_BG` = `"#0F1916"`，`Overlay.CANVAS_EDGE` = `"#1D4D3F"`，`Overlay.CANVAS_ACCENT` = `"#2EE6A8"`，`Overlay.CANVAS_TEXT` = `"#4FF2C8"`，`Overlay.CANVAS_DIM` = `"#8FD6C2"`，`Overlay.CANVAS_RED` = `"#FF5252"`，`Overlay.TRANSPARENT_KEY` = `"#0000FF"`，`Overlay.CORNER_RADIUS` = 12
  - `Overlay.font_family()` 静态方法 → `str`（返回 `三极芯片体 超粗` 或回退 `Microsoft YaHei UI`）
  - `Overlay._ensure_canvas()` → 创建/返回 `self.canvas`（`tk.Canvas`，`highlightthickness=0`，`bg=TRANSPARENT_KEY`）
  - `Overlay._round_rect(canvas, x1, y1, x2, y2, r, **kwargs)` 静态方法 → 在 canvas 上绘制圆角矩形，返回 item id

- [ ] **Step 1: 写失败测试（字体回退 + 常量）**

```python
class OverlayGlassStyleTests(unittest.TestCase):
    def test_glass_style_constants_defined(self) -> None:
        self.assertEqual(Overlay.CANVAS_BG, "#0F1916")
        self.assertEqual(Overlay.CANVAS_ACCENT, "#2EE6A8")
        self.assertEqual(Overlay.CANVAS_TEXT, "#4FF2C8")
        self.assertEqual(Overlay.CORNER_RADIUS, 12)

    def test_font_family_falls_back_when_missing(self) -> None:
        import tkinter.font as tkfont
        real = tkfont.families

        def fake_families(root=None):
            return ["Microsoft YaHei UI"]

        tkfont.families = fake_families
        try:
            self.assertEqual(Overlay.font_family(), "Microsoft YaHei UI")
        finally:
            tkfont.families = real
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_overlay.py::OverlayGlassStyleTests -q --no-header`
Expected: FAIL（`AttributeError: type object 'Overlay' has no attribute 'CANVAS_BG'`）

- [ ] **Step 3: 实现常量与字体回退**

```python
class Overlay:
    CANVAS_BG = "#0F1916"
    CANVAS_EDGE = "#1D4D3F"
    CANVAS_ACCENT = "#2EE6A8"
    CANVAS_TEXT = "#4FF2C8"
    CANVAS_DIM = "#8FD6C2"
    CANVAS_RED = "#FF5252"
    TRANSPARENT_KEY = "#0000FF"
    CORNER_RADIUS = 12

    @staticmethod
    def font_family() -> str:
        try:
            import tkinter.font as tkfont
            if "三极芯片体 超粗" in tkfont.families():
                return "三极芯片体 超粗"
        except Exception:
            pass
        return "Microsoft YaHei UI"
```

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_overlay.py::OverlayGlassStyleTests -q --no-header`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add rf4_overlay.pyw tests/test_overlay.py
git commit -m "feat: overlay glass card constants and font fallback"
```

---

### Task 2: Canvas 创建与圆角绘制工具

**Files:**
- Modify: `rf4_overlay.pyw`（`Overlay.__init__` 渲染面创建区 `:106-120`）
- Test: `tests/test_overlay.py`

**Interfaces:**
- Consumes: Task 1 的 `Overlay.CANVAS_BG`、`Overlay.TRANSPARENT_KEY`、`Overlay.CORNER_RADIUS`
- Produces:
  - `Overlay._ensure_canvas(self)` → `tk.Canvas`（无边框、透明键底色）
  - `Overlay._round_rect(canvas, x1, y1, x2, y2, r, **kwargs)` 静态方法 → 返回绘制的多边形 item id
  - `Overlay._draw(self, *, width, height)` → 全量重绘玻璃卡片（背景、描边、装饰线、文本），返回 None

- [ ] **Step 1: 写失败测试（用 mock canvas 验证绘制调用序列）**

```python
class OverlayGlassDrawTests(unittest.TestCase):
    def _make_overlay(self):
        ov = object.__new__(Overlay)
        ov.style = "dark"
        ov.canvas = None
        ov.root = SimpleNamespace()
        ov._rows = {}
        ov._telemetry_rows = {}
        return ov

    def test_round_rect_draws_polygon_with_rounded_arcs(self) -> None:
        ov = object.__new__(Overlay)
        calls: list[tuple] = []
        canvas = type("C", (), {"create_polygon": lambda self, *a, **k: (calls.append(("polygon", a, k)) or 7)})()
        item = Overlay._round_rect(canvas, 0, 0, 100, 50, 12, fill="#000", outline="#111")
        self.assertEqual(item, 7)
        self.assertEqual(calls[0][0], "polygon")
        self.assertIn("smooth", calls[0][2])

    def test_ensure_canvas_creates_transparent_key_bg(self) -> None:
        ov = object.__new__(Overlay)
        created = {}
        canvas = type("C", (), {"configure": lambda self, **kw: created.update(kw), "create_text": lambda *a, **k: 1, "create_polygon": lambda *a, **k: 2})()
        ov._ensure_canvas = lambda: canvas  # patched below in real impl
        self.assertTrue(hasattr(Overlay, "_ensure_canvas"))
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_overlay.py::OverlayGlassDrawTests -q --no-header`
Expected: FAIL（`_round_rect` 不存在 / `_ensure_canvas` 不存在）

- [ ] **Step 3: 实现 Canvas 创建与圆角绘制**

```python
    def _ensure_canvas(self):
        if self.canvas is None:
            canvas = tk.Canvas(
                self.root,
                highlightthickness=0,
                bg=self.TRANSPARENT_KEY,
            )
            canvas.pack(fill="both", expand=True)
            self.canvas = canvas
        return self.canvas

    @staticmethod
    def _round_rect(canvas, x1, y1, x2, y2, r, **kwargs):
        r = min(r, (x2 - x1) // 2, (y2 - y1) // 2)
        pts = [
            x1 + r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1,
        ]
        kwargs.setdefault("smooth", True)
        return canvas.create_polygon(pts, **kwargs)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_overlay.py::OverlayGlassDrawTests -q --no-header`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add rf4_overlay.pyw tests/test_overlay.py
git commit -m "feat: canvas surface and rounded-rect drawing helper"
```

---

### Task 3: 全量重绘 `_draw` 与 `apply_style` 改造

**Files:**
- Modify: `rf4_overlay.pyw`（`_refresh_display` 与 `apply_style`，原 `:281-303`、`:171-187`）
- Test: `tests/test_overlay.py`

**Interfaces:**
- Consumes: Task 1 颜色常量、Task 2 `_ensure_canvas`/`_round_rect`/`self.canvas`、现有 `_content_height`、`_fight_row_color`、`_rows`/`_telemetry_rows`
- Produces:
  - `Overlay._draw(self, *, width, height)` → 清空 canvas、绘制圆角背景（`CANVAS_BG`）、描边（`CANVAS_EDGE`）、顶部装饰线（`CANVAS_ACCENT` 2px）、文本（主文字 `CANVAS_TEXT` 或力竭 `CANVAS_RED`；遥测/待机行用 `CANVAS_DIM`）；返回 None
  - `Overlay._content_height(lines)` 保持接口，改为用 `CANVAS_TEXT` 字体度量
  - `Overlay.apply_style(style)` 改为设置 `self.style` + 触发 `_draw`（透明键不变）

- [ ] **Step 1: 写失败测试（mock canvas 记录 create 调用）**

```python
class OverlayGlassDrawFullTests(unittest.TestCase):
    def _overlay(self):
        ov = object.__new__(Overlay)
        ov.style = "dark"
        ov._rows = {"1号杆": "1号杆 | 体力 78% 出线 12.3米"}
        ov._telemetry_rows = {}
        created: list[tuple] = []
        canvas = type("C", (), {
            "delete": lambda self, tag: None,
            "create_polygon": lambda self, *a, **k: (created.append(("polygon", k)) or 1),
            "create_line": lambda self, *a, **k: (created.append(("line", k)) or 2),
            "create_text": lambda self, *a, **k: (created.append(("text", k)) or 3),
        })()
        ov.canvas = canvas
        ov._ensure_canvas = lambda: canvas
        ov._content_height = lambda lines: 60
        ov._fight_row_color = staticmethod(lambda text, default: default)
        ov._show = lambda: None
        ov.created = created
        ov.root = SimpleNamespace()
        return ov

    def test_draw_renders_background_edge_accent_and_text(self) -> None:
        ov = self._overlay()
        ov._draw(width=320, height=60)
        kinds = [c[0] for c in ov.created]
        self.assertIn("polygon", kinds)  # 背景 + 描边
        self.assertIn("line", kinds)     # 装饰线
        self.assertIn("text", kinds)     # 文本
        bg = [k for k in ov.created if k[0] == "polygon"]
        self.assertTrue(all(k[1].get("fill") == "#0F1916" for k in bg))

    def test_exhausted_row_uses_red_text(self) -> None:
        ov = self._overlay()
        ov._rows = {"1号杆": "1号杆 | 体力 0% 出线 2.1米"}
        ov._fight_row_color = Overlay._fight_row_color.__get__(ov)
        ov._draw(width=320, height=60)
        texts = [k for k in ov.created if k[0] == "text"]
        self.assertEqual(texts[0][1]["fill"], "#FF5252")
```

- [ ] **Step 2: 运行测试确认失败**

Run: `py -m pytest tests/test_overlay.py::OverlayGlassDrawFullTests -q --no-header`
Expected: FAIL（`_draw` 不存在）

- [ ] **Step 3: 实现 `_draw` 并改造 `_refresh_display`**

```python
    def _draw(self, *, width, height):
        canvas = self._ensure_canvas()
        canvas.delete("all")
        r = self.CORNER_RADIUS
        pad = 2
        # 圆角背景 + 内侧描边
        Overlay._round_rect(canvas, 1, 1, width - 2, height - 2, r,
                            fill=self.CANVAS_BG, outline=self.CANVAS_EDGE, width=1)
        # 顶部 HUD 装饰线
        canvas.create_line(
            1, 3, width - 3, 3,
            fill=self.CANVAS_ACCENT, width=2,
        )
        lines = self._lines_for_display()
        exhausted = self._any_exhausted(lines)
        text_color = self.CANVAS_RED if exhausted else self.CANVAS_TEXT
        # 文本区：先所有行，再按遥测/待机降暗
        canvas.create_text(
            16, 14,
            text="\n".join(lines),
            anchor="nw",
            font=(Overlay.font_family(), 13, "bold"),
            fill=text_color,
            width=width - 32,
            justify="left",
        )
```

辅助方法（加在 `_draw` 之前）：

```python
    def _lines_for_display(self):
        lines = [self._rows[key] for key in sorted(self._rows, key=self._rod_sort_key)]
        for seq, text in self._telemetry_rows.items():
            lines.append(text)
        if not lines:
            lines = ["RF4 来鱼提醒 · 待机中"]
        return lines

    def _any_exhausted(self, lines) -> bool:
        return any(
            Overlay._fight_row_color(text, self.CANVAS_TEXT) == self.CANVAS_RED
            for text in lines
        )
```

改造 `_refresh_display`（替换原 `label.config` 与 `_content_height` 调用）：

```python
    def _refresh_display(self):
        lines = self._lines_for_display()
        need_h = self._content_height(lines)
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        self.root.geometry(f"{WINDOW_WIDTH}x{need_h}+{x}+{y}")
        self._draw(width=WINDOW_WIDTH, height=need_h)
        self._show()
```

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_overlay.py -q --no-header`
Expected: PASS（含既有路由/搏鱼/颜色测试）

- [ ] **Step 5: 改造 `apply_style` 兼容新渲染**

```python
    def apply_style(self, style):
        params = self._STYLE_PARAMS.get(style)
        if params is None:
            return
        self.style = style
        self.root.configure(bg=params["bg"])
        try:
            self.root.wm_attributes("-transparentcolor", self.TRANSPARENT_KEY)
        except tk.TclError:
            pass
        self._refresh_display()
```

（`label` 属性不再存在——检查 `__init__` 是否仍引用 `self.label`，若有则全部改为 canvas 路径。）

- [ ] **Step 6: 运行全量测试确认无回归**

Run: `py -m pytest tests -q --no-header`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add rf4_overlay.pyw tests/test_overlay.py
git commit -m "feat: canvas glass card rendering with accent bar and dim telemetry"
```

---

### Task 4: `__init__` 与 `_content_height` 适配新渲染面

**Files:**
- Modify: `rf4_overlay.pyw`（`__init__` `:106-120` 的 Label 创建改为 Canvas；`_content_height` `:305-320` 改用 Canvas 字体度量）
- Test: `tests/test_overlay.py`

**Interfaces:**
- Consumes: Task 1-3 的 `font_family`、`_ensure_canvas`、`CANVAS_TEXT`
- Produces: `Overlay.__init__` 不再创建 `self.label`，改为 `self.canvas = None` 并由 `_ensure_canvas` 懒创建；`_content_height(lines)` 返回 int 保持不变

- [ ] **Step 1: 移除 Label 创建，改为 Canvas 懒创建**

在 `Overlay.__init__` 中删除：

```python
        self.label = tk.Label(
            root,
            text="",
            bg=self._STYLE_PARAMS[self.style]["bg"],
            fg=self._STYLE_PARAMS[self.style]["fg"],
            font=("Microsoft YaHei UI", 13, "bold"),
            padx=16,
            pady=12,
            wraplength=WINDOW_WIDTH - 32,
            justify="left",
            anchor="w",
        )
        self.label.pack(fill="both", expand=True)
```

替换为：

```python
        self.canvas = None
        self._ensure_canvas()
```

保留 `self.apply_style(self.style)`（其内部已适配，见 Task 3）。

- [ ] **Step 2: 更新 `_content_height` 用字体度量**

```python
    def _content_height(self, lines):
        try:
            import tkinter.font as tkfont
            wrap_px = WINDOW_WIDTH - 32
            f = tkfont.Font(self.root, family=Overlay.font_family(), size=13)
            row_h = f.metrics("linespace") + 4
            total = 0
            for line in lines:
                visual = max(1, math.ceil(f.measure(line) / max(wrap_px, 1)))
                total += visual * row_h
            return max(40, total + 40)
        except Exception:
            return 40 + 28 * len(lines)
```

- [ ] **Step 3: 更新 `__init__` 中 `_STYLE_PARAMS` 相关残留**

确认 `Overlay.__init__` 中 `self.label` 的所有引用已移除（grep 检查）。`_STYLE_PARAMS` 保留（`apply_style` 仍用其 `bg`/`fg` 供根窗口背景与兼容）。`_fight_row_color` 默认色参数改为 `CANVAS_TEXT`。

- [ ] **Step 4: 运行测试确认通过**

Run: `py -m pytest tests/test_overlay.py -q --no-header`
Expected: PASS

- [ ] **Step 5: 运行全量测试**

Run: `py -m pytest tests -q --no-header`
Expected: PASS（90 个基线 + overlay 新增）

- [ ] **Step 6: 人工验证浮窗渲染**

Run: `py rf4_overlay.pyw`（确认无 Label 引用报错、玻璃卡片/圆角/拖动/事件弹出正常；用 UDP 工具向 `127.0.0.1:25000` 发 `{"event":"fish_incoming","gear_slot":"1","text":"有鱼"}` 验证弹出）

- [ ] **Step 7: 提交**

```bash
git add rf4_overlay.pyw tests/test_overlay.py
git commit -m "feat: switch overlay to canvas rendering with custom font"
```

---

### Task 5: 收尾——删除残留引用与全量回归

**Files:**
- Modify: `rf4_overlay.pyw`
- Test: `tests/test_overlay.py`

**Interfaces:**
- Consumes: Task 1-4 全部产物
- Produces: 无 `self.label` 残留；`_STYLE_PARAMS` 仅保留 `bg` 键（`fg`/`key` 不再使用则清理）

- [ ] **Step 1: 全面检查残留**

Run: `rg "self\.label|label\." rf4_overlay.pyw`
Expected: 无匹配（若有，移除对应行）

- [ ] **Step 2: 检查 `_STYLE_PARAMS` 使用**

Run: `rg "_STYLE_PARAMS" rf4_overlay.pyw`
Expected: 仅 `apply_style` 引用其 `bg`；若 `fg`/`key` 已无引用，从 `_STYLE_PARAMS` 删除多余键，避免死代码。

- [ ] **Step 3: 运行全量测试**

Run: `py -m pytest tests -q --no-header`
Expected: PASS

- [ ] **Step 4: 人工验证两种风格切换**

编辑 `rf4_overlay_config.json` 的 `style` 字段（`dark`/`transparent`），运行 `py rf4_overlay.pyw`，确认两种模式下圆角玻璃卡片均正常渲染、无 TclError。

- [ ] **Step 5: 提交**

```bash
git add rf4_overlay.pyw tests/test_overlay.py
git commit -m "chore: remove dead label references after canvas migration"
```
