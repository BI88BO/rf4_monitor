"""进程挂起控制：SuspendThread 挂起/恢复游戏进程，行为对齐参考版「F4雷达」。"""
from __future__ import annotations

import ctypes
import json
import os
import queue
import threading
from ctypes import wintypes as wt
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_PROCESS_NAMES = ("rf4_x64.exe",)

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
# 首选键被别的程序占用时按这个顺序顺延，绑上哪个键就显示哪个。
# 参考版首选 F7，本机 F7 常被别的程序占着，所以首选仍是 F8，F7 放最后兜底。
HOTKEY_FALLBACK_KEYS = ("F8", "F9", "F6", "F5", "F7")


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
    hotkey: str = "F8"

    @classmethod
    def from_dict(cls, data: object) -> "SuspendConfig":
        raw = data if isinstance(data, dict) else {}
        names = raw.get("process_names", DEFAULT_PROCESS_NAMES)
        if isinstance(names, str):
            names = [names]
        if not isinstance(names, list) or not names:
            names = list(DEFAULT_PROCESS_NAMES)
        hotkey = str(raw.get("hotkey", "")).strip().upper() or "F8"
        return cls(
            enabled=bool(raw.get("enabled", True)),
            process_names=tuple(
                str(name).lower() for name in names if str(name).strip()
            ),
            hotkey=hotkey,
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
    """F8 挂起控制器 + 来鱼流程：来鱼解冻，咬钩自动冻回去。

    挂起后按 F8 是唯一的手动开关；来鱼流程是自动的：
      挂起 →(fish_incoming) 解冻并待命 →(fish_bitten) 再挂起，鱼冻在咬钩那一帧，
      玩家有不限时看浮窗，要拉杆再按 F8。待命期间按 F8 视为玩家接管，自动解除待命。
    除热键外，只有挂起线程自己会调 Win32：Tk 事件线程只往 _actions 投递动作，
    由 tick() 取出执行，两个线程不会并发操作同一批线程句柄。
    """

    def __init__(self, process: ProcessSuspender, config: SuspendConfig) -> None:
        self.process = process
        self.config = config
        self.suspended = False
        self.armed = False
        self.error = ""
        # 热键注册成功后由浮窗改成真正绑上的键（首选键被占用时会顺延）。
        self.hotkey_label = config.hotkey
        self.fish_notes: list[str] = []
        self._actions: queue.Queue[tuple[str, str]] = queue.Queue()

    def request(self, action: str, label: str = "") -> None:
        """Tk 线程投递动作（release/freeze/disarm），真正的挂起在 tick 里做。"""
        self._actions.put((action, label))

    def note_fish(self, label: str) -> None:
        """咬钩冻住的竿号只给状态行显示，不参与挂起判断。

        整表替换而不是原地 append：写的人是挂起线程，读的人是 Tk 线程，
        重新赋值在 GIL 下原子，读到的必是完整的前一版或后一版。
        """
        if not label or label in self.fish_notes:
            return
        self.fish_notes = [*self.fish_notes, label]

    def start(self) -> bool:
        self.armed = False
        self.fish_notes = []
        if not self.process.suspend():
            self.suspended = False
            names = "/".join(self.config.process_names) or "游戏进程"
            self.error = f"未找到 {names} 或挂起失败，游戏启动后再按 {self.hotkey_label}"
            return False
        self.error = ""
        self.suspended = True
        return True

    def stop(self) -> bool:
        self.armed = False
        self.fish_notes = []
        if not self.suspended:
            self.error = ""
            return False
        resumed = self.process.resume()
        self.suspended = False
        self.error = "" if resumed else "游戏进程恢复失败"
        return resumed

    def detach(self) -> None:
        """停止本控制器接管，但保留当前挂起状态，由用户手动恢复。"""
        self.armed = False
        self.fish_notes = []
        self.error = ""

    def toggle(self) -> bool:
        # 待命时按热键算玩家自己接管：不再自动冻回去。
        self.armed = False
        if self.suspended:
            return self.stop()
        return self.start()

    def tick(self) -> None:
        while True:
            try:
                action, label = self._actions.get_nowait()
            except queue.Empty:
                return
            if action == "release":
                # 只在真的冻着、而且不是为拉杆冻着的时候解冻。
                if self.suspended and not self.fish_notes:
                    self.stop()
                    self.armed = True
            elif action == "freeze":
                if self.armed:
                    self.armed = False
                    if not self.suspended:
                        self.start()
                    self.note_fish(label)
                elif self.suspended and self.fish_notes:
                    # 已经为拉杆冻住了：别的竿再咬钩只多标一笔，不动冻结状态。
                    self.note_fish(label)
            elif action == "disarm":
                self.armed = False

    def status_text(self) -> str:
        if self.error:
            return self.error
        notes = self.fish_notes
        if self.suspended:
            if notes:
                return f"游戏已挂起 · {'、'.join(notes)}，按 {self.hotkey_label} 拉杆"
            return f"游戏已挂起（{self.hotkey_label} 恢复）"
        if self.armed:
            return "等待咬钩，咬钩自动挂起"
        return ""


class GlobalHotkey:
    """注册系统级热键；按下后由浮窗轮询消费。

    首选键被别的程序占用时按 HOTKEY_FALLBACK_KEYS 顺延，绑上哪个键就写在
    bound_key 里，浮窗的状态文本跟着显示。
    """

    def __init__(
        self,
        hotkey: str = "F8",
        fallbacks: Sequence[str] = HOTKEY_FALLBACK_KEYS,
    ) -> None:
        self.hotkey = hotkey.upper()
        self.fallbacks = tuple(str(key).upper() for key in fallbacks)
        self.bound_key = ""
        self.triggered = threading.Event()
        self._stop = threading.Event()
        self._registered = threading.Event()
        self._thread: threading.Thread | None = None

    def _candidates(self) -> tuple[str, ...]:
        keys = [self.hotkey, *self.fallbacks]
        return tuple(dict.fromkeys(key for key in keys if key))

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
        user32 = ctypes.windll.user32
        for key in self._candidates():
            try:
                modifiers, vk = self._key_parts(key)
            except ValueError:
                continue
            if not user32.RegisterHotKey(None, HOTKEY_ID, modifiers, vk):
                continue
            self.bound_key = key
            self._registered.set()
            try:
                self._message_loop(user32)
            finally:
                user32.UnregisterHotKey(None, HOTKEY_ID)
            return

    def _message_loop(self, user32) -> None:
        message = wt.MSG()
        while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
            if message.message == WM_HOTKEY and message.wParam == HOTKEY_ID:
                self.triggered.set()

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
