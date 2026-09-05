"""进程挂起控制：从旧 RF4 工具移植的 F8 挂起/恢复功能。"""
from __future__ import annotations

import ctypes
import json
import os
import threading
import time
from ctypes import wintypes as wt
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_PROCESS_NAMES = ("rf4_x64.exe",)
DEFAULT_COUNTDOWN_SECONDS = 60.0
DEFAULT_REHANG_DELAY_SECONDS = 0.05

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
WM_HOTKEY = 0x0312
WM_QUIT = 0x0012
HOTKEY_ID = 0x4D4F  # "MO"，仅作为当前进程消息队列里的本地 id
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wt.ULONG)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class _ThreadEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ThreadID", wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wt.DWORD),
    ]


def _configure_windows_api() -> None:
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(_ProcessEntry)]
    kernel32.Process32FirstW.restype = wt.BOOL
    kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(_ProcessEntry)]
    kernel32.Process32NextW.restype = wt.BOOL
    kernel32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(_ThreadEntry)]
    kernel32.Thread32First.restype = wt.BOOL
    kernel32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_ThreadEntry)]
    kernel32.Thread32Next.restype = wt.BOOL
    kernel32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenThread.restype = wt.HANDLE
    kernel32.SuspendThread.argtypes = [wt.HANDLE]
    kernel32.SuspendThread.restype = wt.DWORD
    kernel32.ResumeThread.argtypes = [wt.HANDLE]
    kernel32.ResumeThread.restype = wt.DWORD
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL


def _configure_hotkey_api() -> None:
    user32 = ctypes.windll.user32
    user32.RegisterHotKey.argtypes = [wt.HWND, ctypes.c_int, wt.UINT, wt.UINT]
    user32.RegisterHotKey.restype = wt.BOOL
    user32.UnregisterHotKey.argtypes = [wt.HWND, ctypes.c_int]
    user32.UnregisterHotKey.restype = wt.BOOL
    user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
    user32.GetMessageW.restype = ctypes.c_ssize_t
    user32.PostThreadMessageW.argtypes = [wt.DWORD, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.PostThreadMessageW.restype = wt.BOOL


@dataclass(frozen=True)
class SuspendConfig:
    enabled: bool = True
    process_names: tuple[str, ...] = DEFAULT_PROCESS_NAMES
    loop_enabled: bool = True
    countdown_seconds: float = DEFAULT_COUNTDOWN_SECONDS
    rehang_delay_seconds: float = DEFAULT_REHANG_DELAY_SECONDS

    @classmethod
    def from_dict(cls, data: object) -> "SuspendConfig":
        raw = data if isinstance(data, dict) else {}
        names = raw.get("process_names", DEFAULT_PROCESS_NAMES)
        if isinstance(names, str):
            names = [names]
        if not isinstance(names, list) or not names:
            names = list(DEFAULT_PROCESS_NAMES)
        return cls(
            enabled=bool(raw.get("enabled", True)),
            process_names=tuple(
                str(name).lower() for name in names if str(name).strip()
            ),
            loop_enabled=bool(raw.get("loop_enabled", True)),
            countdown_seconds=max(
                0.0, float(raw.get("countdown_seconds", DEFAULT_COUNTDOWN_SECONDS))
            ),
            rehang_delay_seconds=max(
                0.0,
                float(raw.get("rehang_delay_seconds", DEFAULT_REHANG_DELAY_SECONDS)),
            ),
        )

    @classmethod
    def load(
        cls, path: Path = PACKAGE_DIR / "rf4_config.json"
    ) -> "SuspendConfig":
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            return cls()
        return cls.from_dict(
            data.get("process_suspend") if isinstance(data, dict) else {}
        )


class ProcessSuspender:
    """按旧工具的逻辑枚举目标进程线程，并用 TID 记录挂起/恢复。"""

    def __init__(
        self, process_names: Sequence[str] = DEFAULT_PROCESS_NAMES
    ) -> None:
        self.process_names = tuple(name.lower() for name in process_names)
        self.last_pid: int | None = None
        self.last_tids: tuple[int, ...] = ()
        if os.name == "nt":
            _configure_windows_api()

    def find_pid(self) -> int | None:
        if os.name != "nt":
            return None
        kernel32 = ctypes.windll.kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == INVALID_HANDLE_VALUE:
            return None
        try:
            entry = _ProcessEntry()
            entry.dwSize = ctypes.sizeof(_ProcessEntry)
            if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                return None
            while True:
                if entry.szExeFile.lower() in self.process_names:
                    return int(entry.th32ProcessID)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    return None
        finally:
            kernel32.CloseHandle(snapshot)

    def enumerate_threads(self, pid: int) -> tuple[int, ...]:
        if os.name != "nt":
            return ()
        kernel32 = ctypes.windll.kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if not snapshot or snapshot == INVALID_HANDLE_VALUE:
            return ()
        tids: list[int] = []
        try:
            entry = _ThreadEntry()
            entry.dwSize = ctypes.sizeof(_ThreadEntry)
            if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
                return ()
            while True:
                if entry.th32OwnerProcessID == pid:
                    tids.append(int(entry.th32ThreadID))
                if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                    break
        finally:
            kernel32.CloseHandle(snapshot)
        return tuple(tids)

    def suspend(self) -> bool:
        pid = self.find_pid()
        if pid is None:
            return False
        tids = self.enumerate_threads(pid)
        if not tids:
            return False
        self.last_pid = pid
        self.last_tids = tids
        kernel32 = ctypes.windll.kernel32
        success = 0
        for tid in sorted(tids):
            handle = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
            if not handle:
                continue
            try:
                if kernel32.SuspendThread(handle) != 0xFFFFFFFF:
                    success += 1
            finally:
                kernel32.CloseHandle(handle)
        return success > 0

    def resume(self) -> bool:
        tids = self.last_tids
        if not tids:
            return False
        kernel32 = ctypes.windll.kernel32
        success = 0
        for tid in reversed(tids):
            handle = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
            if not handle:
                continue
            try:
                if kernel32.ResumeThread(handle) != 0xFFFFFFFF:
                    success += 1
            finally:
                kernel32.CloseHandle(handle)
        self.last_tids = ()
        self.last_pid = None
        return success > 0


class SuspendLoop:
    """F8 状态机：挂起 → 倒计时 → 恢复 → 短暂延迟 → 再挂起。"""

    def __init__(
        self,
        process: ProcessSuspender,
        config: SuspendConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.process = process
        self.config = config
        self.clock = clock
        self.suspended = False
        self.active = False
        self.phase = ""
        self.deadline = 0.0

    def start(self) -> bool:
        if not self.process.suspend():
            self.suspended = False
            self.active = False
            self.phase = ""
            self.deadline = 0.0
            return False
        self.suspended = True
        if self.config.loop_enabled:
            self.active = True
            self.phase = "countdown"
            self.deadline = self.clock() + self.config.countdown_seconds
        else:
            self.active = False
            self.phase = ""
            self.deadline = 0.0
        return True

    def stop(self) -> bool:
        self.active = False
        self.phase = ""
        self.deadline = 0.0
        if not self.suspended:
            return False
        resumed = self.process.resume()
        self.suspended = False
        return resumed

    def detach(self) -> None:
        """停止本控制器接管，但保留当前挂起状态，由用户手动恢复。"""
        self.active = False
        self.phase = ""
        self.deadline = 0.0

    def toggle(self) -> bool:
        if self.suspended:
            return self.stop()
        return self.start()

    def tick(self) -> None:
        if not self.active:
            return
        now = self.clock()
        if now < self.deadline:
            return
        if self.phase == "countdown":
            self.process.resume()
            self.suspended = False
            self.phase = "delay"
            self.deadline = now + self.config.rehang_delay_seconds
        elif self.phase == "delay":
            if not self.process.suspend():
                self.active = False
                self.phase = ""
                self.deadline = 0.0
                return
            self.suspended = True
            self.phase = "countdown"
            self.deadline = now + self.config.countdown_seconds

    def status_text(self) -> str:
        if self.active:
            remaining = max(0.0, self.deadline - self.clock())
            text = str(int(remaining)) if remaining >= 1.0 else "<1"
            return f"{'已挂起' if self.suspended else '待挂起'} {text}"
        if self.suspended:
            return "已挂起"
        return ""


class GlobalHotkey:
    """注册进程级全局热键；F8 按下后由浮窗轮询消费。"""

    def __init__(self, hotkey: str = "F8") -> None:
        self.hotkey = hotkey.upper()
        self.triggered = threading.Event()
        self._stop = threading.Event()
        self._registered = threading.Event()
        self._thread: threading.Thread | None = None

    @staticmethod
    def _key_parts(hotkey: str) -> tuple[int, int]:
        parts = [part.strip().upper() for part in hotkey.split("+")]
        if not parts:
            raise ValueError("hotkey is empty")
        vk = 0
        modifiers = 0
        for part in parts:
            if part == "CTRL":
                modifiers |= MOD_CONTROL
            elif part == "ALT":
                modifiers |= MOD_ALT
            elif part == "SHIFT":
                modifiers |= MOD_SHIFT
            elif len(part) == 1 and part in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
                vk = ord(part)
            elif part.startswith("F") and part[1:].isdigit():
                index = int(part[1:])
                if not 1 <= index <= 24:
                    raise ValueError(f"unsupported F-key: {part}")
                vk = 0x70 + index - 1
            else:
                raise ValueError(f"unsupported hotkey part: {part}")
        if vk == 0:
            raise ValueError("hotkey has no main key")
        return modifiers, vk

    def _worker(self) -> None:
        if os.name != "nt":
            return
        _configure_hotkey_api()
        try:
            modifiers, vk = self._key_parts(self.hotkey)
        except ValueError:
            return
        user32 = ctypes.windll.user32
        if not user32.RegisterHotKey(None, HOTKEY_ID, modifiers, vk):
            return
        self._registered.set()
        message = wt.MSG()
        while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
            if message.message == WM_HOTKEY and message.wParam == HOTKEY_ID:
                self.triggered.set()

        user32.UnregisterHotKey(None, HOTKEY_ID)

    def start(self) -> bool:
        if os.name != "nt":
            return False
        self._thread = threading.Thread(target=self._worker, name="rf4-hotkey", daemon=True)
        self._thread.start()
        self._registered.wait(timeout=0.2)
        return self._registered.is_set()

    def poll(self) -> bool:
        if not self.triggered.is_set():
            return False
        self.triggered.clear()
        return True

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            user32 = ctypes.windll.user32
            user32.PostThreadMessageW(thread.native_id, WM_QUIT, 0, 0)
            thread.join(timeout=0.5)
        self._thread = None
