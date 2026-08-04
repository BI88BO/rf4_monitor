import hashlib
import os
import re
import sys
from datetime import datetime

_WINDOWS_VT_MODE_READY = False


def _enable_windows_virtual_terminal() -> bool:
    global _WINDOWS_VT_MODE_READY
    if _WINDOWS_VT_MODE_READY:
        return True
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle in (0, -1):
            return False
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        if kernel32.SetConsoleMode(handle, mode.value | 0x0004) == 0:
            return False
    except Exception:
        return False
    _WINDOWS_VT_MODE_READY = True
    return True


def _stream_is_tty(stream) -> bool:
    if stream is None:
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def _supports_colored_console_output() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not (_stream_is_tty(getattr(sys, "stdout", None)) or _stream_is_tty(getattr(sys, "stderr", None))):
        return False
    return _enable_windows_virtual_terminal()


def _colorize_console_text(text: str, color_code: str) -> str:
    if not _supports_colored_console_output():
        return text
    return f"\033[{color_code}m{text}\033[0m"


OUTPUT_CATEGORY_LABELS = {
    "status": "状态",
    "info": "信息",
    "event": "鱼获",
    "self": "钓鱼",
    "fish": "钓鱼",
    "player": "人物",
    "feed": "投喂",
    "chat": "聊天",
    "room": "房间",
    "session": "会话",
    "unknown": "未知",
    "debug": "调试",
    "warning": "警告",
    "error": "错误",
}
OUTPUT_CATEGORY_COLORS = {
    "status": "90",
    "info": "90",
    "event": "92",
    "self": "93",
    "fish": "93",
    "player": "94",
    "feed": "95",
    "chat": "92",
    "room": "36",
    "session": "90",
    "unknown": "90",
    "debug": "90",
    "warning": "93",
    "error": "91",
}

FISHING_ROD_COLORS = {
    1: "92;1",
    2: "96;1",
    3: "95;1",
    4: "94;1",
    5: "93;1",
    6: "91;1",
    7: "97;1",
}

FISH_GRADE_COLORS = {
    "[不达标]": "90",
    "[达标]": "92",
    "[稀有★]": "93;1",
    "[超级稀有◆]": "96;1",
}


def _colorize_fishing_line(text: str) -> str:
    if not _supports_colored_console_output():
        return text
    rendered = text
    rod_match = re.search(r"\[(\d+|\?)号竿\]", rendered)
    if rod_match:
        rod_text = rod_match.group(0)
        rod_number = int(rod_match.group(1)) if rod_match.group(1).isdigit() else None
        rod_color = FISHING_ROD_COLORS.get(rod_number, "90")
        rendered = rendered.replace(rod_text, f"\033[{rod_color}m{rod_text}\033[0m", 1)
    for grade, color in FISH_GRADE_COLORS.items():
        if grade in rendered:
            rendered = rendered.replace(grade, f"\033[{color}m{grade}\033[0m", 1)
            break
    return rendered


def format_console_line(category: str, text: str, *, timestamp: datetime | None = None) -> str:
    """Render one stable, grep-friendly console line with optional ANSI color."""
    normalized = category.strip().lower() or "status"
    label = OUTPUT_CATEGORY_LABELS.get(normalized, normalized)
    clock = (timestamp or datetime.now()).strftime("%H:%M:%S")
    prefix = f"{clock} [{label}]"
    color = OUTPUT_CATEGORY_COLORS.get(normalized, "")
    if color:
        prefix = _colorize_console_text(prefix, color)
    if normalized in {"fish", "self"}:
        text = _colorize_fishing_line(text)
    return f"{prefix} {text}"


def mask_secret(value: str) -> str:
    """Return a safe identifier for a secret without exposing reusable material."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"sha256:{digest} (长度 {len(value)})"

