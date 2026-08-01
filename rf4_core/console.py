import os
import sys

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
    if not (_stream_is_tty(getattr(sys, "stdout", None)) or _stream_is_tty(getattr(sys, "stderr", None))):
        return False
    return _enable_windows_virtual_terminal()


def _colorize_console_text(text: str, color_code: str) -> str:
    if not _supports_colored_console_output():
        return text
    return f"\033[{color_code}m{text}\033[0m"

