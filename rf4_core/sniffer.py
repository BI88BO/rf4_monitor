from __future__ import annotations

import copy
import ipaddress
import os
import queue
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import ctypes

from . import bridge as _bridge_mod
from .bridge import FlowSession, RF4ChatBridge
from .console import format_console_line, mask_secret
from .protocol import (
    get_profile,
    parse_envelope,
    take_complete_frames,
    try_parse_auth_packet,
    try_parse_first_frame,
    try_parse_uuid_packet,
    u32,
)

THIS_DIR = Path(__file__).resolve().parent
_SCRIPT_DIR = THIS_DIR.parent

core = SimpleNamespace(
    ctx=None,
    FlowSession=FlowSession,
    RF4ChatBridge=RF4ChatBridge,
    format_console_line=format_console_line,
    mask_secret=mask_secret,
    get_profile=get_profile,
    parse_envelope=parse_envelope,
    take_complete_frames=take_complete_frames,
    try_parse_auth_packet=try_parse_auth_packet,
    try_parse_first_frame=try_parse_first_frame,
    try_parse_uuid_packet=try_parse_uuid_packet,
)


MAX_HANDSHAKE_BUFFER = 1024 * 1024
MAX_PENDING_TCP_BYTES = 8 * 1024 * 1024
DISCOVERY_TIMEOUT_SECONDS = 30.0
DISCOVERY_MAX_STREAM_BYTES = 256 * 1024
DISCOVERY_MAX_CANDIDATES = 2048
DYNAMIC_INTERFACE_SCAN_SECONDS = 1.0
TCP_GAP_WARNING_SECONDS = 2.0
# 缺口出现后优先等待 TCP 重传补齐（游戏客户端会一直等数据包重新到位），
# 超过该阈值才跳过缺口继续解析；重传慢时缺口内帧内容可能丢失。
TCP_GAP_RECOVERY_SECONDS = 15.0
MAX_RECOVERABLE_TCP_GAP_BYTES = 4096
# 下行序号缺口持续超过该值时判定为真丢包（非乱序），RC4 流已不可恢复，
# 冻结下行解析并提示用户重新登录游戏；等待下次 realtime 重连自动恢复。
TCP_GAP_STALL_SECONDS = 45.0
VIRTUAL_INTERFACE_HINTS = (
    "accelerator",
    "clash",
    "game",
    "tap",
    "tun",
    "vpn",
    "wintun",
    "加速",
    "奇游",
    "雷神",
    "迅游",
)
IGNORED_INTERFACE_HINTS = (
    "bluetooth",
    "host-only",
    "hyper-v",
    "virtualbox",
    "vmnet",
    "vmware",
    "wi-fi direct",
)

Endpoint = tuple[str, int]
FlowKey = tuple[Endpoint, Endpoint]

# 内存 RC4 handoff：游戏 realtime 自动切服（负载均衡/会话迁移）时新连接直接
# 续传已加密业务流、不重新 auth 握手。旧会话关闭前保存的 RC4 快照按 token
# 索引，切服新连接用同一 token 重建 RC4 后搜索真实帧边界继续解析。
RC4_HANDOFF_MAX_AGE_SECONDS = 24 * 60 * 60
RC4_HANDOFF_MAX_ENTRIES = 16
# 无 auth 切服恢复时搜索帧边界的最大密文字节数（0..上限）。
CACHED_TOKEN_RESYNC_SKIP_BYTES = 64 * 1024
CACHED_TOKEN_RESYNC_MAX_BYTES = 1024 * 1024
CACHED_TOKEN_RESYNC_ENVELOPE_PREFIX_BYTES = 11
# 每个方向独立搜索帧边界；同时限制单个包处理内的扫描工作量。
CACHED_TOKEN_RESYNC_WORK_BUDGET = 1024
# 无 auth 切服恢复失败后的重试冷却：bootstrap 探测很贵（遍历全部保存的
# handoff × 预算次 RC4 解密），切服连接持续有流量时若每包都重试会打满 CPU。
# 只在 candidate 生命周期内按该间隔重试，其余包直接跳过探测。
HANDOFF_BOOTSTRAP_RETRY_SECONDS = 5.0


@dataclass(frozen=True)
class CapturedTcpPacket:
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    payload: bytes
    flags: int


def _parse_raw_eth_tcp_packet(raw: bytes) -> Optional[CapturedTcpPacket]:
    """Parse an Ethernet-framed IPv4/IPv6 TCP packet without Scapy overhead.

    Npcap delivers raw Ethernet frames; Scapy's ``sniff`` wraps every frame in
    full Packet objects which are slow to construct at high packet rates.  This
    lightweight parser extracts exactly the fields ``PacketObserver`` needs and
    mirrors ``_windivert_packet_to_capture`` so the capture path stays fast.
    """
    if len(raw) < 14:
        return None
    ethertype = (raw[12] << 8) | raw[13]
    if ethertype == 0x0800:
        return _parse_ipv4_tcp_packet(raw[14:])
    if ethertype == 0x86DD:
        return _parse_ipv6_tcp_packet(raw[14:])
    return None


def _parse_ipv4_tcp_packet(data: bytes) -> Optional[CapturedTcpPacket]:
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl + 20:
        return None
    protocol = data[9]
    if protocol != 6:
        return None
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    tcp = data[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack("!HHI", tcp[:8])
    offset = ((tcp[12] >> 4) & 0x0F) * 4
    if offset < 20 or len(tcp) < offset:
        return None
    flags = tcp[13]
    payload = tcp[offset:]
    return CapturedTcpPacket(
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        seq=seq,
        payload=payload,
        flags=flags,
    )


def _parse_ipv6_tcp_packet(data: bytes) -> Optional[CapturedTcpPacket]:
    if len(data) < 40:
        return None
    next_header = data[6]
    if next_header != 6:
        return None
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    tcp = data[40:]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack("!HHI", tcp[:8])
    offset = ((tcp[12] >> 4) & 0x0F) * 4
    if offset < 20 or len(tcp) < offset:
        return None
    flags = tcp[13]
    payload = tcp[offset:]
    return CapturedTcpPacket(
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        seq=seq,
        payload=payload,
        flags=flags,
    )


def _print_line(category: str, text: str) -> None:
    line = core.format_console_line(category, text)
    print(line, flush=True)
    if getattr(core, "_sniffer_log_fh", None) is not None:
        try:
            core._sniffer_log_fh.write(line + "\n")
            core._sniffer_log_fh.flush()
        except Exception:
            pass


def _open_sniffer_log() -> None:
    """Tee passive output to logs/rf4_sniffer.log, mirroring launcher's log file."""
    try:
        if getattr(sys, "frozen", False):
            log_dir = Path(sys.executable).resolve().parent / "logs"
        else:
            log_dir = _SCRIPT_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        target = log_dir / "rf4_sniffer.log"
    except Exception:
        return
    try:
        core._sniffer_log_fh = open(target, "w", encoding="utf-8", buffering=1)
    except Exception:
        core._sniffer_log_fh = None


class PacketDispatcher:
    """Move protocol parsing off Npcap callback threads to avoid capture stalls."""

    def __init__(self, observer: "PacketObserver", max_queue_size: int) -> None:
        self.observer = observer
        self.queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.dropped_packets = 0
        self.worker = threading.Thread(
            target=self._consume,
            name="rf4-packet-parser",
            daemon=True,
        )
        self.worker.start()

    def submit(self, packet) -> None:
        try:
            self.queue.put_nowait(packet)
        except queue.Full:
            self.dropped_packets += 1
            _print_line_once(
                self,
                "capture-queue-full",
                "error",
                "抓包处理队列已满，已发生本地丢包；请减少抓包接口或增大 --capture-queue-size",
            )

    def _consume(self) -> None:
        while True:
            packet = self.queue.get()
            try:
                self.observer.handle_packet(packet)
            finally:
                self.queue.task_done()


_PCAP_STATS_INTERVAL_SECONDS = 10.0


class PcapDropMonitor:
    """Periodically read Npcap ``pcap_stats`` to surface kernel-side drops.

    Windows Npcap captures run inside the kernel NPF driver; packets dropped
    there never reach user space and are invisible to the reassembler.  A
    periodic ``pcap_stats`` read distinguishes "buffered but dropped by the
    kernel" (ps_drop/ps_ifdrop) from "never delivered by the 802.11 driver",
    which is exactly what we need after the wireless driver upgrade.
    """

    _instance: Optional["PcapDropMonitor"] = None

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handles: list[tuple[str, int]] = []
        self._last_stats: dict[int, tuple[int, int, int]] = {}
        self._reported_once = False
        self._thread: Optional[threading.Thread] = None

    @classmethod
    def instance(cls) -> "PcapDropMonitor":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, handle) -> None:
        try:
            if handle is None or not handle:
                return
            handle = int(ctypes.cast(handle, ctypes.c_void_p).value or 0)
        except Exception:
            return
        if not handle:
            return
        with self._lock:
            if handle not in self._last_stats:
                self._last_stats[handle] = (0, 0, 0)
            if handle not in self._handles:
                self._handles.append(handle)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="rf4-pcap-stats",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        while True:
            time.sleep(_PCAP_STATS_INTERVAL_SECONDS)
            try:
                self._sample()
            except Exception:
                pass

    def _sample(self) -> None:
        from scapy.libs.winpcapy import pcap_stats  # local import: lazy Npcap

        try:
            fn = pcap_stats
            fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            fn.restype = ctypes.c_int
        except Exception:
            return
        stat = _PcapStat()
        with self._lock:
            handles = list(self._handles)
        total_recv = total_drop = total_ifdrop = 0
        active = []
        for handle in handles:
            try:
                rc = fn(handle, ctypes.byref(stat))
            except Exception:
                rc = -1
            if rc != 0:
                continue
            recv, drop, ifdrop = stat.ps_recv, stat.ps_drop, stat.ps_ifdrop
            last = self._last_stats.get(handle, (0, 0, 0))
            self._last_stats[handle] = (recv, drop, ifdrop)
            d_recv = recv - last[0]
            d_drop = drop - last[1]
            d_ifdrop = ifdrop - last[2]
            total_recv += d_recv
            total_drop += d_drop
            total_ifdrop += d_ifdrop
            active.append((handle, d_recv, d_drop, d_ifdrop))
        if not active:
            return
        summary = (
            f"Npcap 内核统计: 收包+{total_recv} 内核丢弃+{total_drop} "
            f"驱动丢弃+{total_ifdrop} / 间隔{int(_PCAP_STATS_INTERVAL_SECONDS)}s"
        )
        if total_drop or total_ifdrop:
            _print_line(
                "warning",
                f"{summary}（存在内核级丢包，抓包缓冲可能不足或无线驱动丢帧）",
            )
        else:
            if not self._reported_once:
                _print_line("status", summary)
                self._reported_once = True


class _PcapStat(ctypes.Structure):
    _fields_ = [
        ("ps_recv", ctypes.c_uint),
        ("ps_drop", ctypes.c_uint),
        ("ps_ifdrop", ctypes.c_uint),
    ]


class NpcapRawCaptor:
    """Low-overhead Npcap reader bypassing Scapy's full Packet construction.

    Scapy 2.7.0's ``_PcapWrapper_libpcap`` sets snaplen/promisc/timeout but
    never calls ``pcap_set_buffer_size``, so ``conf.bufsize`` (our advertised
    64MB) never reaches the kernel and the default small NPF buffer overflows
    during traffic bursts, dropping the game's downlink segments.  This captor
    drives the WinPcap/Npcap C API directly: a real kernel buffer plus raw
    Ethernet frames parsed by ``_parse_raw_eth_tcp_packet`` instead of Scapy
    Packet objects.
    """

    def __init__(self, *, buffer_mb: int = 64, snaplen: int = 262144) -> None:
        self.buffer_mb = buffer_mb
        self.snaplen = snaplen
        self._handle = None

    def open(self, device_name: str, *, packet_filter: str = "tcp") -> None:
        from scapy.libs.winpcapy import (
            pcap_activate,
            pcap_create,
            pcap_set_buffer_size,
            pcap_set_promisc,
            pcap_set_snaplen,
            pcap_set_timeout,
        )

        errbuf = ctypes.create_string_buffer(256)
        handle = pcap_create(device_name.encode("utf8"), errbuf)
        if not handle:
            raise OSError(self._err_text(errbuf))

        def _set(fn, value):
            rc = int(fn(handle, value))
            if rc != 0:
                raise OSError(f"{fn.__name__} rc={rc}")

        _set(pcap_set_snaplen, self.snaplen)
        _set(pcap_set_promisc, 0)
        _set(pcap_set_timeout, 100)
        if self.buffer_mb > 0:
            _set(pcap_set_buffer_size, self.buffer_mb * 1024 * 1024)
        status = int(pcap_activate(handle))
        if status < 0:
            raise OSError(f"pcap_activate rc={status}")
        if packet_filter:
            self._apply_filter(handle, packet_filter)
        self._handle = handle
        PcapDropMonitor.instance().register(handle)
        from scapy.libs.winpcapy import pcap_setmintocopy

        try:
            pcap_setmintocopy(handle, 0)
        except Exception:
            pass

    @staticmethod
    def _call(fn, *args) -> int:
        return int(fn(*args))

    @staticmethod
    def _err_text(errbuf) -> str:
        try:
            return bytes(errbuf).split(b"\x00")[0].decode("utf8", errors="replace")
        except Exception:
            return "unknown error"

    def _apply_filter(self, handle, packet_filter: str) -> None:
        from scapy.libs.winpcapy import bpf_program, pcap_compile, pcap_setfilter

        netmask = 0xFFFFFFFF
        program = bpf_program()
        rc = pcap_compile(handle, program, packet_filter.encode("utf8"), 1, netmask)
        if rc != 0:
            raise OSError("pcap_compile failed: filter not supported")
        try:
            rc = pcap_setfilter(handle, ctypes.byref(program))
        finally:
            self._free_bpf(program)
        if rc != 0:
            raise OSError("pcap_setfilter failed")

    @staticmethod
    def _free_bpf(program) -> None:
        from scapy.libs.winpcapy import pcap_freecode

        try:
            pcap_freecode(ctypes.byref(program))
        except Exception:
            pass

    def recv_loop(self, handler) -> None:
        from scapy.libs.winpcapy import pcap_next_ex, pcap_pkthdr

        pkt_header = ctypes.POINTER(pcap_pkthdr)()
        pkt_data = ctypes.POINTER(ctypes.c_ubyte)()
        while self._handle is not None:
            rc = pcap_next_ex(
                self._handle,
                ctypes.byref(pkt_header),
                ctypes.byref(pkt_data),
            )
            if rc == 1:
                size = int(pkt_header.contents.caplen)
                if size:
                    raw = ctypes.string_at(pkt_data, size)
                    packet = _parse_raw_eth_tcp_packet(raw)
                    if packet is not None:
                        handler(packet)
            elif rc == 0:
                time.sleep(0.0005)
            else:
                return

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        from scapy.libs.winpcapy import pcap_close

        try:
            pcap_close(handle)
        except Exception:
            pass


def _install_pcap_stats_hook() -> None:
    """Record every opened Npcap handle so PcapDropMonitor can read pcap_stats."""
    try:
        from scapy.arch.libpcap import _PcapWrapper_libpcap
    except Exception:
        return

    original_init = _PcapWrapper_libpcap.__init__

    def patched_init(self, *args, **kwargs) -> None:
        original_init(self, *args, **kwargs)
        handle = getattr(self, "pcap", None)
        if handle:
            PcapDropMonitor.instance().register(handle)

    _PcapWrapper_libpcap.__init__ = patched_init


@dataclass
class TcpStreamReassembler:
    """Small in-order TCP payload reassembler with retransmission handling."""

    next_seq: Optional[int] = None
    fragments: dict[int, bytes] = field(default_factory=dict)
    pending_bytes: int = 0
    gap_started_at: Optional[float] = None

    def reset(self, initial_seq: Optional[int] = None) -> None:
        self.next_seq = initial_seq
        self.fragments.clear()
        self.pending_bytes = 0
        self.gap_started_at = None

    def feed(self, seq: int, payload: bytes, *, syn: bool = False) -> bytes:
        payload_seq = seq + (1 if syn else 0)
        if self.next_seq is None:
            self.next_seq = payload_seq
        if not payload:
            return b""

        assert self.next_seq is not None
        end_seq = payload_seq + len(payload)
        if end_seq <= self.next_seq:
            return b""
        if payload_seq < self.next_seq:
            payload = payload[self.next_seq - payload_seq :]
            payload_seq = self.next_seq

        previous = self.fragments.get(payload_seq)
        if previous is None or len(payload) > len(previous):
            if previous is not None:
                self.pending_bytes -= len(previous)
            self.fragments[payload_seq] = payload
            self.pending_bytes += len(payload)
        if self.pending_bytes > MAX_PENDING_TCP_BYTES:
            raise BufferError("TCP 乱序缓存超过 8 MiB；抓包可能从会话中途开始或丢包过多")

        out = bytearray()
        while self.fragments:
            assert self.next_seq is not None
            usable_starts = [start for start in self.fragments if start <= self.next_seq]
            if not usable_starts:
                if self.gap_started_at is None:
                    self.gap_started_at = time.monotonic()
                break
            self.gap_started_at = None
            start = min(usable_starts)
            fragment = self.fragments.pop(start)
            self.pending_bytes -= len(fragment)
            fragment_end = start + len(fragment)
            if fragment_end <= self.next_seq:
                continue
            offset = self.next_seq - start
            fresh = fragment[offset:]
            out.extend(fresh)
            self.next_seq += len(fresh)

        if not self.fragments:
            self.gap_started_at = None

        return bytes(out)

    def gap_age(self) -> float:
        if self.gap_started_at is None:
            return 0.0
        return max(0.0, time.monotonic() - self.gap_started_at)

    def first_pending_seq(self) -> Optional[int]:
        return min(self.fragments) if self.fragments else None

    def recover_gap(self, *, max_gap_bytes: int) -> tuple[int, bytes]:
        if self.next_seq is None or not self.fragments:
            return 0, b""
        pending_seq = self.first_pending_seq()
        if pending_seq is None or pending_seq <= self.next_seq:
            return 0, b""
        gap_bytes = pending_seq - self.next_seq
        if gap_bytes <= 0 or gap_bytes > max_gap_bytes:
            return 0, b""
        pending = self.fragments.pop(pending_seq)
        self.pending_bytes -= len(pending)
        self.next_seq = pending_seq + len(pending)
        self.gap_started_at = None

        out = bytearray(pending)
        while self.fragments:
            usable_starts = [start for start in self.fragments if start <= self.next_seq]
            if not usable_starts:
                break
            start = min(usable_starts)
            fragment = self.fragments.pop(start)
            self.pending_bytes -= len(fragment)
            fragment_end = start + len(fragment)
            if fragment_end <= self.next_seq:
                continue
            offset = self.next_seq - start
            fresh = fragment[offset:]
            out.extend(fresh)
            self.next_seq += len(fresh)
        if not self.fragments:
            self.gap_started_at = None
        return gap_bytes, bytes(out)

    def chain_pending_data(self, *, max_bytes: int) -> bytes:
        """Return the contiguous run of buffered fragments starting at the gap,
        without consuming them. Mirrors ``recover_gap`` chaining so a resync scan
        can find a frame boundary even when it lives in a later TCP segment."""
        if self.next_seq is None or not self.fragments:
            return b""
        pending_seq = self.first_pending_seq()
        if pending_seq is None or pending_seq <= self.next_seq:
            return b""
        out = bytearray()
        cursor = pending_seq
        consumed: set[int] = set()
        while len(out) < max_bytes:
            usable_starts = [
                start for start in self.fragments if start <= cursor and start not in consumed
            ]
            if not usable_starts:
                break
            start = min(usable_starts)
            fragment = self.fragments[start]
            fragment_end = start + len(fragment)
            consumed.add(start)
            if fragment_end <= cursor:
                continue
            offset = cursor - start
            fresh = fragment[offset:]
            out.extend(fresh)
            cursor += len(fresh)
        return bytes(out)


@dataclass
class PassiveSession:
    session_id: str
    bridge: core.RF4ChatBridge
    protocol: core.FlowSession
    client_tcp: TcpStreamReassembler = field(default_factory=TcpStreamReassembler)
    server_tcp: TcpStreamReassembler = field(default_factory=TcpStreamReassembler)
    failed: bool = False
    downlink_stalled: bool = False
    decrypted_frames: int = 0
    valid_business_frames: int = 0
    invalid_business_frames: int = 0
    valid_client_frames: int = 0
    valid_server_frames: int = 0
    invalid_client_frames: int = 0
    invalid_server_frames: int = 0
    warned_tcp_gaps: set[str] = field(default_factory=set)

    @classmethod
    def create(cls, session_id: str, bridge: core.RF4ChatBridge) -> "PassiveSession":
        return cls(
            session_id=session_id,
            bridge=bridge,
            protocol=core.FlowSession(profile=bridge._profile),
        )

    @property
    def flow(self):
        return SimpleNamespace(id=self.session_id)

    def feed_tcp(self, *, from_client: bool, seq: int, payload: bytes, syn: bool) -> None:
        reassembler = self.client_tcp if from_client else self.server_tcp
        chunk = reassembler.feed(seq, payload, syn=syn)
        direction = "客户端上行" if from_client else "服务器下行"
        if (
            reassembler.gap_age() >= TCP_GAP_WARNING_SECONDS
            and direction not in self.warned_tcp_gaps
        ):
            self.warned_tcp_gaps.add(direction)
            _print_line(
                "warning",
                f"{direction} TCP 抓包存在序号缺口，等待自动重同步恢复"
                f" | 等待序号={reassembler.next_seq}"
                f" 已见后续序号={reassembler.first_pending_seq()}"
                f" 缓存={reassembler.pending_bytes}字节"
                f" | 会话={self.session_id}"
                f" | 说明：小缺口将自动跳过并重同步 RC4，无需重连；若持续 45 秒未恢复才需重新登录",
            )
        if not chunk and reassembler.gap_age() >= TCP_GAP_RECOVERY_SECONDS:
            gap_bytes, chunk = self._recover_tcp_gap(
                reassembler, from_client=from_client, direction=direction
            )
            if gap_bytes:
                _print_line(
                    "warning",
                    f"{direction} 已跳过 {gap_bytes} 字节 TCP 缺口，丢弃当前不完整业务帧后继续尝试解析"
                    f" | 会话={self.session_id}",
                )
        if not from_client and not self.downlink_stalled:
            # 下行序号缺口持续超阈值仍未填补 = 真丢包（非乱序），RC4 流不可恢复。
            # 冻结该会话下行解析，避免来鱼推送被静默吞掉；等下次 realtime 重连自动恢复。
            if (
                reassembler.pending_bytes
                and reassembler.gap_age() >= TCP_GAP_STALL_SECONDS
            ):
                self.downlink_stalled = True
                self.warned_tcp_gaps.add(direction)
                _print_line(
                    "warning",
                    f"服务器下行已因序号缺口失步，来鱼推送暂时无法显示"
                    f" | 等待序号={reassembler.next_seq}"
                    f" 已见后续序号={reassembler.first_pending_seq()}"
                    f" | 会话={self.session_id}"
                    f" | 提示：请重新登录游戏，下次 realtime 重连将自动恢复",
                )
        if not chunk:
            return
        if from_client:
            self._process_client_bytes(chunk)
        elif not self.downlink_stalled:
            self._process_server_bytes(chunk)

    def _recover_tcp_gap(
        self,
        reassembler: TcpStreamReassembler,
        *,
        from_client: bool,
        direction: str,
    ) -> tuple[int, bytes]:
        session = self.protocol
        if not session.handshake_complete():
            return 0, b""
        pending_seq = reassembler.first_pending_seq()
        if reassembler.next_seq is None or pending_seq is None:
            return 0, b""
        gap_bytes = pending_seq - reassembler.next_seq
        if gap_bytes <= 0 or gap_bytes > MAX_RECOVERABLE_TCP_GAP_BYTES:
            if gap_bytes > MAX_RECOVERABLE_TCP_GAP_BYTES:
                _print_line(
                    "warning",
                    f"{direction} TCP 缺口 {gap_bytes} 字节过大，放弃实验性恢复 | 会话={self.session_id}",
                )
            return 0, b""
        cipher = session.client_read_rc4 if from_client else session.server_read_rc4
        if cipher is None:
            return 0, b""
        # 信封验证重同步：缺口内混有明文帧头时，盲目 keystream(gap_bytes)
        # 会高估密文字节数导致后续全部错位。改为在缺口后数据里找帧边界，
        # 对候选密文跳过量逐一校验 parse_envelope，命中才同步。
        # 缺口后数据可能被拆成多个 TCP 段，帧边界可能落在后续片段里，
        # 因此必须把所有连续片段拼接起来扫描，而不能只看第一个片段。
        pending_seq = reassembler.first_pending_seq()
        if pending_seq is None:
            return 0, b""
        pending_data = reassembler.chain_pending_data(
            max_bytes=MAX_RECOVERABLE_TCP_GAP_BYTES * 4
        )
        if not pending_data:
            return 0, b""
        resync = self._resync_gap_cipher(cipher, pending_data, gap_bytes)
        if resync is None:
            _print_line(
                "warning",
                f"{direction} TCP 缺口 {gap_bytes} 字节无法通过信封校验重同步，放弃恢复 | 会话={self.session_id}",
            )
            return 0, b""
        lost, fpos = resync
        cipher.keystream(lost + fpos)
        buffer = session.client_buffer if from_client else session.server_buffer
        buffer.clear()
        gap_bytes, chunk = reassembler.recover_gap(max_gap_bytes=MAX_RECOVERABLE_TCP_GAP_BYTES)
        return gap_bytes, chunk[fpos:]

    @staticmethod
    def _resync_gap_cipher(
        cipher: object,
        pending_data: bytes,
        gap_bytes: int,
    ) -> Optional[tuple[int, int]]:
        """在缺口后数据里找第一个完整帧边界，对候选密文跳过量逐一信封校验。

        返回 (缺口内密文字节数, 帧边界前的残留密文字节数)，找不到可验证帧返回 None。
        """
        candidates: list[int] = []
        for fpos in range(len(pending_data)):
            if fpos + 4 > len(pending_data):
                break
            body_len = u32(pending_data, fpos)
            if body_len == 1 or body_len < 9:
                continue
            if fpos + 4 + body_len > len(pending_data):
                continue
            candidates.append(fpos)
        if not candidates:
            return None
        for fpos in candidates:
            body_len = u32(pending_data, fpos)
            payload = pending_data[fpos + 13 : fpos + 13 + body_len - 9]
            for lost in range(gap_bytes + 1):
                probe = copy.deepcopy(cipher)
                probe.keystream(lost + fpos)
                if parse_envelope(probe.crypt(payload)) is not None:
                    return lost, fpos
        return None

    def _print_once_reset(self) -> None:
        seen = getattr(self, "_printed_messages", None)
        if seen is None:
            seen = set()
            setattr(self, "_printed_messages", seen)
        if "overlay-reset" in seen:
            return
        seen.add("overlay-reset")
        try:
            self.bridge.broadcast_reset()
        except Exception:
            pass

    def _process_client_bytes(self, chunk: bytes) -> None:
        session = self.protocol
        session.client_buffer.extend(chunk)

        if not session.auth_seen:
            parsed = core.try_parse_auth_packet(bytes(session.client_buffer))
            if parsed is None:
                self._check_handshake_buffer(session.client_buffer, "token")
                return
            token, consumed = parsed
            session.token = token
            session.auth_seen = True
            del session.client_buffer[:consumed]
            _print_line("session", f"认证握手已捕获 | token={core.mask_secret(token)} | 会话={self.session_id}")

        if session.auth_seen and not session.hermes_seen:
            frame = core.try_parse_first_frame(bytes(session.client_buffer))
            if frame is None:
                self._check_handshake_buffer(session.client_buffer, "Hermes")
                return
            if b"<hermes>" not in frame.payload:
                raise ValueError("认证包后未找到 Hermes 明文握手；协议版本可能已变化")
            del session.client_buffer[: len(frame.raw)]
            session.hermes_seen = True
            session.ensure_rc4()

        if session.handshake_complete():
            _print_line_once(self, "handshake-announced", "session", f"握手完成，开始验证加密业务流量 | 会话={self.session_id}")
            self._print_once_reset()
            self._decode_frames(from_client=True)
            if session.server_buffer:
                self._decode_frames(from_client=False)

    def _process_server_bytes(self, chunk: bytes) -> None:
        session = self.protocol
        session.server_buffer.extend(chunk)
        if not session.uuid_seen:
            parsed = core.try_parse_uuid_packet(bytes(session.server_buffer))
            if parsed is None:
                self._check_handshake_buffer(session.server_buffer, "UUID")
                return
            _, consumed = parsed
            session.uuid_seen = True
            del session.server_buffer[:consumed]

        if session.handshake_complete():
            _print_line_once(self, "handshake-announced", "session", f"握手完成，开始验证加密业务流量 | 会话={self.session_id}")
            self._print_once_reset()
            self._decode_frames(from_client=False)
            if session.client_buffer:
                self._decode_frames(from_client=True)

    def _decode_frames(self, *, from_client: bool) -> None:
        session = self.protocol
        buffer = session.client_buffer if from_client else session.server_buffer
        frames = core.take_complete_frames(buffer)
        cipher = session.client_read_rc4 if from_client else session.server_read_rc4
        if cipher is None:
            raise ValueError("RC4 状态尚未初始化")

        for frame in frames:
            if frame.frame_type == 1 or not frame.payload:
                continue
            plain_body = cipher.crypt(frame.payload)
            self.decrypted_frames += 1
            if core.parse_envelope(plain_body) is not None:
                self.valid_business_frames += 1
                if from_client:
                    self.valid_client_frames += 1
                else:
                    self.valid_server_frames += 1
                if self.valid_client_frames and self.valid_server_frames:
                    _print_line_once(
                        self,
                        "decryption-validated-both",
                        "session",
                        f"双向解密验证成功，业务协议解析正常 | 会话={self.session_id}",
                    )
                elif from_client:
                    _print_line_once(
                        self,
                        "decryption-validated-client",
                        "session",
                        f"客户端上行解密验证成功，等待服务器下行流量 | 会话={self.session_id}",
                    )
                else:
                    _print_line_once(
                        self,
                        "decryption-validated-server",
                        "session",
                        f"服务器下行解密验证成功，等待客户端上行流量 | 会话={self.session_id}",
                    )
            else:
                self.invalid_business_frames += 1
                if from_client:
                    self.invalid_client_frames += 1
                    direction_invalid = self.invalid_client_frames
                    direction_valid = self.valid_client_frames
                    direction_label = "客户端上行"
                    message_key = "decryption-invalid-client"
                else:
                    self.invalid_server_frames += 1
                    direction_invalid = self.invalid_server_frames
                    direction_valid = self.valid_server_frames
                    direction_label = "服务器下行"
                    message_key = "decryption-invalid-server"
                if direction_invalid >= 8 and direction_valid == 0:
                    _print_line_once(
                        self,
                        message_key,
                        "warning",
                        f"{direction_label}连续解密帧未识别为 RF4 业务协议；"
                        "可能丢失了数据包或加速器已切换流量接口"
                        f" | 会话={self.session_id}",
                    )
            self.bridge._maybe_log_telemetry_frame(self.flow, session, from_client, plain_body)
            if bool(getattr(core.ctx.options, "rf4_log_plain_frames", False)):
                self.bridge._log(
                    f"解密帧 {'C->S' if from_client else 'S->C'} | 会话={self.session_id} "
                    f"类型={frame.frame_type} wire={frame.wire_id} 长度={len(plain_body)} "
                    f"{self.bridge._describe_plain_body(plain_body)}"
                )
            if from_client:
                try:
                    self.bridge._track_rpc_request_command(session, plain_body)
                    self.bridge._track_building_rpc_request(session, plain_body)
                except Exception:
                    pass
                self.bridge._handle_client_frame(session, plain_body)
            else:
                self.bridge._handle_server_frame(session, plain_body)

    @staticmethod
    def _check_handshake_buffer(buffer: bytearray, stage: str) -> None:
        if len(buffer) > MAX_HANDSHAKE_BUFFER:
            raise BufferError(f"等待 {stage} 握手时缓存超过 1 MiB；请在游戏连接 realtime 前启动抓包")


def _print_line_once(owner: object, name: str, category: str, text: str) -> None:
    seen = getattr(owner, "_printed_messages", None)
    if seen is None:
        seen = set()
        setattr(owner, "_printed_messages", seen)
    if name in seen:
        return
    seen.add(name)
    _print_line(category, text)


@dataclass
class Rc4Handoff:
    token: str
    client_read_rc4: object
    server_read_rc4: object
    saved_at: float

    @classmethod
    def capture(cls, protocol: FlowSession) -> Optional["Rc4Handoff"]:
        if not protocol.token or protocol.client_read_rc4 is None or protocol.server_read_rc4 is None:
            return None
        return cls(
            token=protocol.token,
            client_read_rc4=protocol.client_read_rc4.clone(),
            server_read_rc4=protocol.server_read_rc4.clone(),
            saved_at=time.monotonic(),
        )


@dataclass
class DiscoveryCandidate:
    endpoints: FlowKey
    created_at: float
    updated_at: float
    suspected_server: Optional[Endpoint] = None
    reconnect_attempt: bool = False
    streams: dict[Endpoint, TcpStreamReassembler] = field(default_factory=dict)
    buffers: dict[Endpoint, bytearray] = field(default_factory=dict)
    last_bootstrap_attempt: Optional[float] = None
    bootstrap_diag_printed: bool = False

    def feed(self, source: Endpoint, *, seq: int, payload: bytes, syn: bool) -> None:
        self.updated_at = time.monotonic()
        stream = self.streams.setdefault(source, TcpStreamReassembler())
        chunk = stream.feed(seq, payload, syn=syn)
        if not chunk:
            return
        buffer = self.buffers.setdefault(source, bytearray())
        buffer.extend(chunk)
        if len(buffer) > DISCOVERY_MAX_STREAM_BYTES:
            raise BufferError("自动识别缓存超过 256 KiB；该连接不像 RF4 realtime 握手")

    def find_auth_endpoint(self) -> Optional[Endpoint]:
        for endpoint, buffer in self.buffers.items():
            # auth 包开头可能是 \x01\x00 或 \x01\x01（游戏在钓鱼站等场景重连
            # realtime 时），与 try_parse_auth_packet 保持一致。
            if len(buffer) >= 2 and buffer[:2] not in (b"\x01\x00", b"\x01\x01"):
                continue
            try:
                parsed = core.try_parse_auth_packet(bytes(buffer))
            except UnicodeDecodeError:
                continue
            if parsed is not None:
                return endpoint
        return None


class PacketObserver:
    def __init__(
        self,
        *,
        realtime_port: int,
        realtime_host: str = "",
        bridge: core.RF4ChatBridge,
    ) -> None:
        self.realtime_port = realtime_port
        self.realtime_host = (realtime_host or "").strip()
        self.realtime_hosts = {value.strip() for value in self.realtime_host.replace(",", ";").split(";") if value.strip()}
        self.bridge = bridge
        self.sessions: dict[tuple[str, int, str, int], PassiveSession] = {}
        self._auto_sessions: dict[FlowKey, tuple[PassiveSession, Endpoint]] = {}
        self._candidates: dict[FlowKey, DiscoveryCandidate] = {}
        self._known_realtime_hosts: set[str] = set()
        self._closed_realtime_hosts: set[str] = set()
        self._reconnect_notified_hosts: set[str] = set()
        self._rc4_handoffs: dict[str, Rc4Handoff] = {}
        self._packets_since_cleanup = 0
        self.total_packets = 0

    def handle_packet(self, packet) -> None:
        try:
            parsed = self._packet_fields(packet)
            if parsed is None:
                return
            src, sport, dst, dport, seq, payload, flags = parsed
            self._packets_since_cleanup += 1
            self.total_packets += 1
            if self._packets_since_cleanup >= 256:
                self._expire_candidates()
                self._packets_since_cleanup = 0
            if self.realtime_port == 0:
                self._handle_auto_packet(src, sport, dst, dport, seq, payload, flags)
                return

            direction = self._classify(src, sport, dst, dport)
            if direction is None:
                return
            from_client, key = direction
            syn = bool(flags & 0x02)
            fin_or_rst = bool(flags & 0x05)

            if syn and from_client:
                self.sessions.pop(key, None)
            session = self.sessions.get(key)
            if session is None:
                session_id = f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}"
                session = PassiveSession.create(session_id, self.bridge)
                self.sessions[key] = session
                _print_line("session", f"发现 realtime 连接 | {session_id}")

            if not session.failed:
                session.feed_tcp(from_client=from_client, seq=seq, payload=payload, syn=syn)
            if fin_or_rst:
                self.sessions.pop(key, None)
                _print_line(
                    "session",
                    f"realtime 连接已关闭 | {self._describe_tcp_close(flags, from_client)} | 会话={session.session_id}",
                )
        except (BufferError, UnicodeDecodeError, ValueError) as exc:
            if "session" in locals():
                session.failed = True
                session_id = session.session_id
            else:
                session_id = "unknown"
            _print_line("error", f"会话解析已停止 | {exc} | 会话={session_id}")
        except Exception as exc:
            if bool(getattr(core.ctx.options, "rf4_verbose_logging", False)):
                _print_line("error", f"数据包处理失败 | {type(exc).__name__}: {exc}")

    def _handle_auto_packet(
        self,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        seq: int,
        payload: bytes,
        flags: int,
    ) -> None:
        # 自动识别模式（realtime_port==0）不依赖硬编码 host 白名单：游戏 realtime
        # 服务器会负载均衡到多个 IP（91.132/185.71/5.35/91.194 等），硬编码列表
        # 会在连接切换到新 IP 时漏掉。改为对所有 TCP 连接按协议特征识别。
        if self.realtime_port != 0 and self.realtime_hosts and src not in self.realtime_hosts and dst not in self.realtime_hosts:
            return

        source = (src, sport)
        destination = (dst, dport)
        key = self._flow_key(source, destination)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin_or_rst = bool(flags & 0x05)

        active = self._auto_sessions.get(key)
        if active is not None and syn and not ack:
            session, client_endpoint = active
            if source == client_endpoint:
                # A fresh client SYN is an authoritative TCP generation boundary.
                # Windows may reuse the same four-tuple before a missed/delayed FIN
                # has retired our old RC4 stream, so never feed it into that state.
                self._remove_auto_session(key, session)
                active = None
        if active is not None:
            session, client_endpoint = active
            session.feed_tcp(
                from_client=source == client_endpoint,
                seq=seq,
                payload=payload,
                syn=syn,
            )
            if fin_or_rst:
                from_client = source == client_endpoint
                self._remove_auto_session(key, session, flags=flags, from_client=from_client)
            return

        if syn and not ack:
            self._candidates.pop(key, None)
        candidate = self._candidates.get(key)
        if candidate is None:
            looks_like_auth = bool(payload[:1] == b"\x01")
            if not (syn and not ack) and not looks_like_auth:
                return
            self._make_candidate_room()
            now = time.monotonic()
            suspected_server = destination
            reconnect_attempt = suspected_server[0] in self._closed_realtime_hosts
            candidate = DiscoveryCandidate(
                key,
                now,
                now,
                suspected_server=suspected_server,
                reconnect_attempt=reconnect_attempt,
            )
            self._candidates[key] = candidate
            if (
                reconnect_attempt
                and suspected_server[0] not in self._reconnect_notified_hosts
            ):
                self._reconnect_notified_hosts.add(suspected_server[0])
                _print_line(
                    "session",
                    "检测到 realtime 重连，等待认证握手 | "
                    f"服务器={suspected_server[0]}:{suspected_server[1]}",
                )

        try:
            candidate.feed(source, seq=seq, payload=payload, syn=syn)
        except BufferError:
            self._candidates.pop(key, None)
            return

        client_endpoint = candidate.find_auth_endpoint()
        if client_endpoint is not None:
            self._promote_candidate(key, candidate, client_endpoint)
            return
        # 无 auth 握手时尝试用最近保存的 RC4 handoff 恢复切服连接。
        if self._try_handoff_bootstrap(key, candidate):
            return
        if fin_or_rst:
            self._candidates.pop(key, None)

    def _promote_candidate(
        self,
        key: FlowKey,
        candidate: DiscoveryCandidate,
        client_endpoint: Endpoint,
    ) -> None:
        server_endpoint = key[1] if key[0] == client_endpoint else key[0]
        oriented_key = (
            client_endpoint[0],
            client_endpoint[1],
            server_endpoint[0],
            server_endpoint[1],
        )
        session_id = (
            f"{client_endpoint[0]}:{client_endpoint[1]} -> "
            f"{server_endpoint[0]}:{server_endpoint[1]}"
        )
        session = PassiveSession.create(session_id, self.bridge)
        session.client_tcp = candidate.streams.setdefault(client_endpoint, TcpStreamReassembler())
        session.server_tcp = candidate.streams.setdefault(server_endpoint, TcpStreamReassembler())
        self.sessions[oriented_key] = session
        self._auto_sessions[key] = (session, client_endpoint)
        self._candidates.pop(key, None)
        self._known_realtime_hosts.add(server_endpoint[0])
        self._closed_realtime_hosts.discard(server_endpoint[0])

        _print_line(
            "session",
            ("realtime 重连已识别" if candidate.reconnect_attempt else "自动识别 realtime")
            + f" | 服务器={server_endpoint[0]}:{server_endpoint[1]} | 会话={session_id}",
        )
        server_data = bytes(candidate.buffers.get(server_endpoint, b""))
        client_data = bytes(candidate.buffers.get(client_endpoint, b""))
        if server_data:
            session._process_server_bytes(server_data)
        if client_data:
            session._process_client_bytes(client_data)

    def _remove_auto_session(
        self,
        key: FlowKey,
        session: PassiveSession,
        flags: Optional[int] = None,
        from_client: Optional[bool] = None,
    ) -> None:
        active = self._auto_sessions.pop(key, None)
        if session.valid_business_frames > 0:
            self._remember_rc4_handoff(session)
        client_endpoint = active[1] if active is not None else None
        server_endpoint = None
        if client_endpoint is not None:
            server_endpoint = key[1] if key[0] == client_endpoint else key[0]
        for oriented_key, candidate_session in list(self.sessions.items()):
            if candidate_session is session:
                self.sessions.pop(oriented_key, None)
                break
        if server_endpoint is not None:
            server_host = server_endpoint[0]
            host_still_active = any(
                (flow_key[1] if flow_key[0] == other_client else flow_key[0])[0]
                == server_host
                for flow_key, (_other_session, other_client) in self._auto_sessions.items()
            )
            if not host_still_active and server_host in self._known_realtime_hosts:
                self._closed_realtime_hosts.add(server_host)
                self._reconnect_notified_hosts.discard(server_host)
        close_detail = ""
        if flags is not None and from_client is not None:
            close_detail = f" | {self._describe_tcp_close(flags, from_client)}"
        _print_line("session", f"realtime 连接已关闭{close_detail} | 会话={session.session_id}")

    def _expire_candidates(self) -> None:
        cutoff = time.monotonic() - DISCOVERY_TIMEOUT_SECONDS
        expired = [key for key, candidate in self._candidates.items() if candidate.updated_at < cutoff]
        for key in expired:
            self._candidates.pop(key, None)

    def _make_candidate_room(self) -> None:
        self._expire_candidates()
        if len(self._candidates) < DISCOVERY_MAX_CANDIDATES:
            return
        oldest_key = min(self._candidates, key=lambda key: self._candidates[key].updated_at)
        self._candidates.pop(oldest_key, None)

    def _remember_rc4_handoff(self, session: PassiveSession) -> None:
        if session.valid_business_frames <= 0:
            return
        handoff = Rc4Handoff.capture(session.protocol)
        if handoff is None:
            return
        self._rc4_handoffs[handoff.token] = handoff
        if len(self._rc4_handoffs) > RC4_HANDOFF_MAX_ENTRIES:
            oldest_key = min(
                self._rc4_handoffs,
                key=lambda key: self._rc4_handoffs[key].saved_at,
            )
            self._rc4_handoffs.pop(oldest_key, None)

    def _take_rc4_handoff(self, token: str) -> Optional[Rc4Handoff]:
        handoff = self._rc4_handoffs.get(token)
        if handoff is None:
            return None
        if time.monotonic() - handoff.saved_at > RC4_HANDOFF_MAX_AGE_SECONDS:
            self._rc4_handoffs.pop(token, None)
            return None
        return handoff

    def _bootstrap_handoff_session(
        self,
        key: FlowKey,
        source: Endpoint,
        destination: Endpoint,
        handoff: Rc4Handoff,
    ) -> Optional[PassiveSession]:
        """切服无 auth 时用内存 RC4 handoff 直接建立会话并返回；返回 None 表示
        handoff 会话已存在或无法确认边界，调用方保持 candidate 状态即可。"""
        active = self._auto_sessions.get(key)
        if active is not None:
            return None
        oriented_key = (
            source[0],
            source[1],
            destination[0],
            destination[1],
        )
        session_id = (
            f"{source[0]}:{source[1]} -> {destination[0]}:{destination[1]}"
        )
        session = PassiveSession.create(session_id, self.bridge)
        session.protocol.token = handoff.token
        session.protocol.auth_seen = True
        session.protocol.uuid_seen = True
        session.protocol.hermes_seen = True
        # 切服后新连接的 RC4 由同一 token 独立派生、从位置 0 开始（与登录时
        # 一致），并非延续旧连接的位置；旧连接的密文位置只用于跨服务器的
        # 会话身份关联。这里用重建的 RC4 流，后续由帧边界搜索对齐。
        session.protocol.ensure_rc4()
        self.sessions[oriented_key] = session
        self._auto_sessions[key] = (session, source)
        self._known_realtime_hosts.add(destination[0])
        self._closed_realtime_hosts.discard(destination[0])
        _print_line(
            "session",
            "realtime 切服已识别（token 重建 RC4，等待帧边界对齐）"
            f" | 服务器={destination[0]}:{destination[1]} | 会话={session_id}",
        )
        return session

    @staticmethod
    def _align_handoff_cipher(
        cipher: object,
        data: bytes,
        *,
        budget: int = CACHED_TOKEN_RESYNC_WORK_BUDGET,
    ) -> Optional[int]:
        """在无 auth 切服的新连接密文流里搜索第一个可验证业务帧的起点。

        从数据流中尝试所有满足 RF4 帧头形状（body_len 合法、非 ACK/控制帧、
        长度足够信封校验）的偏移，对每个偏移用已重建的 RC4（位置 0）从该
        偏移开始解密并校验信封。返回命中的密文帧起点（相对 data 的字节偏移），
        找不到返回 None。

        流开头的 ACK/控制帧（frame_type==1、body_len<=5）是明文，不参与 RC4，
        先按帧结构跳过，再在后续业务帧上校验。
        """
        attempts = 0
        offset = 0
        while offset + 4 <= len(data) and attempts < budget:
            body_len = u32(data, offset)
            if body_len == 0:
                offset += 1
                attempts += 1
                continue
            if body_len == 1:
                # ACK/控制帧：明文 5 字节（body_len=1 + frame_type），跳过。
                offset += 5
                attempts += 1
                continue
            if body_len < 9 or body_len > len(data) - offset - 4:
                offset += 1
                attempts += 1
                continue
            frame_type = data[offset + 4]
            if frame_type == 1:
                offset += 4 + body_len
                attempts += 1
                continue
            payload = data[offset + 13 : offset + 13 + body_len - 9]
            if len(payload) < CACHED_TOKEN_RESYNC_ENVELOPE_PREFIX_BYTES:
                offset += 1
                attempts += 1
                continue
            probe = cipher.clone()
            if parse_envelope(probe.crypt(payload)) is not None:
                return offset
            offset += 1
            attempts += 1
        return None

    def _try_handoff_bootstrap(
        self,
        key: FlowKey,
        candidate: DiscoveryCandidate,
    ) -> bool:
        """尝试用最近保存的 RC4 handoff 把无 auth 的 candidate 提升为会话。

        成功返回 True（candidate 已转正，调用方无需再走 auth 提升路径）。
        仅当候选缓冲已积累足够数据且存在未过期 handoff 时尝试。
        """
        if not self._rc4_handoffs:
            return False
        server_endpoint = candidate.suspected_server
        if server_endpoint is None:
            return False
        client_endpoint = key[0]
        server_data = bytes(candidate.buffers.get(server_endpoint, b""))
        client_data = bytes(candidate.buffers.get(client_endpoint, b""))
        if not server_data and not client_data:
            return False
        # 探测很贵且失败后不改变 candidate 状态；按冷却间隔节流，避免切服连接
        # 持续有流量时每个数据包都全量扫描 RC4 打满 CPU。
        now = time.monotonic()
        last = candidate.last_bootstrap_attempt
        if last is not None and now - last < HANDOFF_BOOTSTRAP_RETRY_SECONDS:
            return False
        candidate.last_bootstrap_attempt = now
        # 服务器下行通常更密集地携带业务帧，优先用它确认 RC4。切服后 RC4 由
        # 同一 token 重建（位置 0），因此用 token 重建的探针校验，而不是旧
        # 连接的密文位置。
        for handoff in list(self._rc4_handoffs.values()):
            probe_protocol = FlowSession(profile=self.bridge._profile)
            probe_protocol.token = handoff.token
            probe_protocol.ensure_rc4()
            probe_server = probe_protocol.server_read_rc4
            frame_offset = self._align_handoff_cipher(probe_server, server_data)
            if frame_offset is None:
                continue
            session = self._bootstrap_handoff_session(
                key,
                source=client_endpoint,
                destination=server_endpoint,
                handoff=handoff,
            )
            if session is None:
                return False
            # 客户端上行同样可能存在明文前置，用重建的 client RC4 对齐。
            client_offset = self._align_handoff_cipher(
                probe_protocol.client_read_rc4, client_data
            )
            # 把候选缓冲喂给新会话（含对齐的帧偏移，丢弃对齐前的明文前置）。
            session.client_tcp = candidate.streams.setdefault(
                client_endpoint, TcpStreamReassembler()
            )
            session.server_tcp = candidate.streams.setdefault(
                server_endpoint, TcpStreamReassembler()
            )
            self._candidates.pop(key, None)
            server_chunk = server_data[frame_offset:]
            if server_chunk:
                session._process_server_bytes(server_chunk)
            if client_data:
                client_chunk = client_data[client_offset:] if client_offset is not None else client_data
                if client_chunk:
                    session._process_client_bytes(client_chunk)
            return True
        # 探测失败：把诊断信息打一次，便于定位切服恢复为何未命中（token 是否
        # 匹配、缓冲是否缺下行数据等）。冷却节流下不会每包刷屏。
        if not candidate.bootstrap_diag_printed:
            candidate.bootstrap_diag_printed = True
            token_names = "/".join(core.mask_secret(h.token) for h in self._rc4_handoffs.values())
            _print_line(
                "session",
                "切服恢复探测未命中 | "
                f"服务器={server_endpoint[0]}:{server_endpoint[1]} | "
                f"下行缓冲={len(server_data)} 字节 上行缓冲={len(client_data)} 字节 | "
                f"已保存 handoff token: {token_names or '(无)'}",
            )
        return False

    @staticmethod
    def _describe_tcp_close(flags: int, from_client: bool) -> str:
        """把 TCP 关闭包标志描述为可读文本，便于区分正常挥手(FIN)与异常复位(RST)。

        在关闭会话时打印，用于定位频繁断线到底是哪一方在复位连接。
        from_client=True 表示关闭包由游戏客户端发出，False 表示由服务器发出。
        """
        kinds = []
        if flags & 0x01:
            kinds.append("FIN")
        if flags & 0x04:
            kinds.append("RST")
        if flags & 0x10:
            kinds.append("ACK")
        kind_text = "+".join(kinds) if kinds else "未知"
        who = "客户端" if from_client else "服务器"
        return f"由{who}发起 flags=0x{int(flags):02x} ({kind_text})"

    @staticmethod
    def _flow_key(first: Endpoint, second: Endpoint) -> FlowKey:
        return (first, second) if first <= second else (second, first)

    def _classify(
        self,
        src: str,
        sport: int,
        dst: str,
        dport: int,
    ) -> Optional[tuple[bool, tuple[str, int, str, int]]]:
        if dport == self.realtime_port and (not self.realtime_hosts or dst in self.realtime_hosts):
            return True, (src, sport, dst, dport)
        if sport == self.realtime_port and (not self.realtime_hosts or src in self.realtime_hosts):
            return False, (dst, dport, src, sport)
        return None

    @staticmethod
    def _packet_fields(packet) -> Optional[tuple[str, int, str, int, int, bytes, int]]:
        if isinstance(packet, CapturedTcpPacket):
            return (
                packet.src,
                packet.sport,
                packet.dst,
                packet.dport,
                packet.seq,
                packet.payload,
                packet.flags,
            )
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6

        if not packet.haslayer(TCP):
            return None
        if packet.haslayer(IP):
            network = packet[IP]
        elif packet.haslayer(IPv6):
            network = packet[IPv6]
        else:
            return None
        tcp = packet[TCP]
        return (
            str(network.src),
            int(tcp.sport),
            str(network.dst),
            int(tcp.dport),
            int(tcp.seq),
            bytes(tcp.payload),
            int(tcp.flags),
        )


def _install_passive_context(args) -> None:
    options = SimpleNamespace(
        rf4_profile=args.profile,
        rf4_enable_chat_bridge=True,
        rf4_enable_login_rewrite=False,
        rf4_enable_self_chat_injection=False,
        rf4_log_parsed_events=True,
        rf4_detailed_output=args.details,
        rf4_log_telemetry=not args.events_only,
        rf4_log_room_protocol_details=args.room_details,
        rf4_log_low_level_telemetry=args.low_level,
        rf4_log_unknown_telemetry=args.unknown,
        rf4_telemetry_categories=args.telemetry_categories,
        rf4_log_plain_frames=args.plain_frames,
        rf4_verbose_logging=args.verbose,
        rf4_event_bridge_host="127.0.0.1",
        rf4_event_bridge_port=0,
        rf4_default_location_id="",
        rf4_default_users_count=0,
        rf4_avatar_url="",
        rf4_sender_level=1,
        rf4_sender_region=1,
        rf4_sender_class=0,
        rf4_sender_badge=0,
    )
    def _ctx_log_info(message: str) -> None:
        text = str(message)
        for prefix in ("\x1b[", "\033["):
            if text.startswith(prefix):
                text = text.split("m", 1)[-1]
                break
        _print_line("info", text)

    core.ctx = SimpleNamespace(
        options=options,
        log=SimpleNamespace(info=_ctx_log_info),
        master=SimpleNamespace(commands=SimpleNamespace(call=lambda *_args, **_kwargs: None)),
    )
    # The bridge module resolves ctx via ``from mitmproxy import ctx``; point it
    # at the passive namespace so proxy-only addon code keeps working offline.
    _bridge_mod.ctx = core.ctx


def list_interfaces() -> int:
    try:
        from scapy.all import get_if_list
    except ImportError:
        _print_line("error", "缺少 scapy，请先运行安装依赖.bat 或 pip install -r requirements.txt")
        return 2
    _print_line("status", "可用抓包接口：")
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list

            for interface in get_windows_if_list():
                name = interface.get("name") or interface.get("guid") or "unknown"
                description = interface.get("description") or ""
                ips = ", ".join(str(value) for value in (interface.get("ips") or []))
                suffix = " | ".join(value for value in (description, ips) if value)
                print(f"  - {name}" + (f" | {suffix}" if suffix else ""))
            return 0
        except Exception:
            pass
    for name in get_if_list():
        print(f"  - {name}")
    return 0


def _select_live_interfaces(requested: str):
    from scapy.all import conf, get_working_ifaces

    if requested:
        return requested, requested
    if sys.platform != "win32":
        interface = conf.iface
        return interface, _interface_label(interface)

    candidates = []
    for interface in get_working_ifaces():
        ipv4_values = list(getattr(interface, "ips", {}).get(4, []))
        usable_ipv4 = []
        for value in ipv4_values:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_link_local or address.is_unspecified:
                continue
            usable_ipv4.append(str(address))
        label_lower = _interface_label(interface).lower()
        if not _is_relevant_capture_interface(label_lower, bool(usable_ipv4)):
            continue
        if _interface_is_disconnected(interface):
            continue
        candidates.append(interface)

    if not candidates:
        # 兜底：至少选一个有可用 IPv4 的接口；都没有则用 scapy 默认接口。
        fallback = None
        for interface in get_working_ifaces():
            ipv4_values = list(getattr(interface, "ips", {}).get(4, []))
            if any(
                not ipaddress.ip_address(v).is_link_local
                for v in ipv4_values
                if _is_valid_ipv4(v)
            ):
                fallback = interface
                break
        interface = fallback or conf.iface
        return interface, _interface_label(interface)
    labels = "; ".join(_interface_label(interface) for interface in candidates)
    return candidates, labels


def _is_valid_ipv4(value) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4


def _is_relevant_capture_interface(label: str, has_usable_ipv4: bool) -> bool:
    normalized = label.lower()
    looks_virtual = any(hint in normalized for hint in VIRTUAL_INTERFACE_HINTS)
    looks_irrelevant = any(hint in normalized for hint in IGNORED_INTERFACE_HINTS)
    if looks_irrelevant and not looks_virtual:
        return False
    if not has_usable_ipv4:
        # 只有 link-local/无 IPv4 的纯虚拟接口（如空闲 TAP/VPN 适配器）不承载
        # 游戏流量，排除它们以减少抓包线程竞争和重复提交导致的乱序丢包。
        if looks_virtual and any(hint in normalized for hint in ("wintun", "wireguard", "tap")):
            return False
        return False
    return True


def _interface_is_disconnected(interface) -> bool:
    """Return True for physical adapters in a disconnected state.

    Scapy exposes the Windows adapter state via the ``flags`` field (e.g.
    ``UP+RUNNING+DISCONNECTED``).  A disconnected adapter can still carry a
    stale non-link-local IPv4 address, which would otherwise make the generic
    IPv4 filter treat it as a usable capture interface and waste a capture
    thread on a link with no game traffic.
    """
    flags = getattr(interface, "flags", None)
    if flags is None:
        return False
    text = str(flags)
    return "DISCONNECTED" in text


def _interface_label(interface) -> str:
    name = getattr(interface, "name", None) or str(interface)
    description = getattr(interface, "description", None) or ""
    ipv4_values = list(getattr(interface, "ips", {}).get(4, []))
    details = [value for value in (description, ",".join(ipv4_values)) if value and value != name]
    return name + (f" ({' | '.join(details)})" if details else "")


def _interface_identity(interface) -> str:
    """Return a stable key across Scapy's periodic Windows interface refreshes."""
    for attribute in ("network_name", "guid", "name"):
        value = getattr(interface, attribute, None)
        if value:
            return str(value)
    return str(interface)


def _interface_list(interfaces) -> list:
    if isinstance(interfaces, (list, tuple, set)):
        return list(interfaces)
    return [interfaces]


def _run_dynamic_windows_capture(
    *,
    sniff,
    observer: PacketObserver,
    initial_interfaces,
    packet_filter: str,
    queue_size: int,
    promiscuous: bool,
    buffer_mb: int = 64,
) -> int:
    """Keep existing Npcap readers alive while adding newly created adapters."""
    workers: dict[str, threading.Thread] = {}
    dispatcher = PacketDispatcher(observer, queue_size)
    initial_keys = {_interface_identity(item) for item in _interface_list(initial_interfaces)}

    def start_worker(interface) -> None:
        identity = _interface_identity(interface)
        label = _interface_label(interface)

        def capture_interface() -> None:
            kwargs = {
                "iface": interface,
                "prn": dispatcher.submit,
                "store": False,
                "filter": packet_filter,
                "promisc": promiscuous,
            }
            try:
                sniff(**kwargs)
            except Exception as exc:
                _print_line(
                    "warning",
                    f"接口内核过滤器不可用，改用用户态识别 | 接口={label} | 原因={exc}",
                )
                kwargs.pop("filter", None)
                try:
                    sniff(**kwargs)
                except Exception as fallback_exc:
                    _print_line("error", f"接口抓包已停止 | 接口={label} | 原因={fallback_exc}")

        worker = threading.Thread(
            target=capture_interface,
            name=f"rf4-capture-{len(workers) + 1}",
            daemon=True,
        )
        workers[identity] = worker
        worker.start()
        if identity not in initial_keys:
            _print_line("status", f"自动加入新抓包接口 | 接口={label}")

    for interface in _interface_list(initial_interfaces):
        start_worker(interface)

    try:
        while True:
            try:
                interfaces, _ = _select_live_interfaces("")
            except Exception as exc:
                _print_line("warning", f"刷新抓包接口失败，稍后自动重试 | 原因={exc}")
                time.sleep(DYNAMIC_INTERFACE_SCAN_SECONDS)
                continue
            for interface in _interface_list(interfaces):
                identity = _interface_identity(interface)
                if identity not in workers:
                    start_worker(interface)
            time.sleep(DYNAMIC_INTERFACE_SCAN_SECONDS)
    except KeyboardInterrupt:
        _print_line("status", "抓包已停止")
        return 0


def _run_npcap_raw_capture(
    *,
    observer: PacketObserver,
    initial_interfaces,
    packet_filter: str,
    queue_size: int,
    buffer_mb: int,
) -> int:
    """Capture Npcap traffic via the low-overhead raw reader.

    Scapy's ``sniff`` constructs a full Packet per frame; on a busy WLAN the
    per-packet cost plus Scapy's failure to set a real kernel buffer
    (``pcap_set_buffer_size`` is never called by Scapy 2.7.0) lets the NPF
    buffer overflow and drops the game's downlink.  This path opens each
    interface with a real kernel buffer and parses raw Ethernet frames.
    """
    dispatcher = PacketDispatcher(observer, queue_size)

    def start_captor(interface, *, label: str) -> None:
        device_name = str(getattr(interface, "network_name", None) or interface)
        captor = NpcapRawCaptor(buffer_mb=buffer_mb)
        try:
            captor.open(device_name, packet_filter=packet_filter)
        except Exception as exc:
            _print_line(
                "error",
                f"接口抓包已停止 | 接口={label} | 原因={exc}",
            )
            return
        captor.recv_loop(dispatcher.submit)
        captor.close()

    initial_keys = {_interface_identity(item) for item in _interface_list(initial_interfaces)}
    workers: dict[str, threading.Thread] = {}

    def spawn(interface) -> None:
        identity = _interface_identity(interface)
        if identity in workers and workers[identity].is_alive():
            return
        label = _interface_label(interface)
        worker = threading.Thread(
            target=start_captor,
            args=(interface,),
            kwargs={"label": label},
            name=f"rf4-capture-{len(workers) + 1}",
            daemon=True,
        )
        workers[identity] = worker
        worker.start()
        if identity not in initial_keys:
            _print_line("status", f"自动加入新抓包接口 | 接口={label}")

    for interface in _interface_list(initial_interfaces):
        spawn(interface)

    try:
        while True:
            try:
                interfaces, _ = _select_live_interfaces("")
            except Exception as exc:
                _print_line("warning", f"刷新抓包接口失败，稍后自动重试 | 原因={exc}")
                time.sleep(DYNAMIC_INTERFACE_SCAN_SECONDS)
                continue
            for interface in _interface_list(interfaces):
                spawn(interface)
            time.sleep(DYNAMIC_INTERFACE_SCAN_SECONDS)
    except KeyboardInterrupt:
        _print_line("status", "抓包已停止")
        return 0


def _windivert_filter(realtime_host: str, realtime_port: int) -> str:
    conditions = [
        "tcp",
        "(tcp.PayloadLength > 0 or tcp.Syn or tcp.Fin or tcp.Rst)",
    ]
    if realtime_port:
        conditions.append(
            f"(tcp.SrcPort == {realtime_port} or tcp.DstPort == {realtime_port})"
        )
    elif realtime_host:
        # 自动识别模式不按 host 白名单过滤：游戏 realtime 服务器会负载均衡到多个
        # IP，硬编码列表在连接切换时漏抓。抓所有 TCP 由用户态按协议特征识别。
        pass
    return " and ".join(conditions)


def _windivert_packet_to_capture(packet) -> Optional[CapturedTcpPacket]:
    tcp_header = getattr(packet, "tcp", None)
    if tcp_header is None:
        return None
    src = getattr(packet, "src_addr", None)
    dst = getattr(packet, "dst_addr", None)
    sport = getattr(packet, "src_port", None)
    dport = getattr(packet, "dst_port", None)
    if src is None or dst is None or sport is None or dport is None:
        return None
    flags = 0
    if bool(getattr(tcp_header, "fin", False)):
        flags |= 0x01
    if bool(getattr(tcp_header, "syn", False)):
        flags |= 0x02
    if bool(getattr(tcp_header, "rst", False)):
        flags |= 0x04
    if bool(getattr(tcp_header, "ack", False)):
        flags |= 0x10
    return CapturedTcpPacket(
        src=str(src),
        sport=int(sport),
        dst=str(dst),
        dport=int(dport),
        seq=int(tcp_header.seq_num),
        payload=bytes(getattr(packet, "payload", None) or b""),
        flags=flags,
    )


def _windivert_read_flags(pydivert) -> tuple[int, str]:
    """Build passive flags across the pydivert/WinDivert versions in use."""
    flags = int(pydivert.Flag.SNIFF)
    recv_only = getattr(pydivert.Flag, "RECV_ONLY", None)
    if recv_only is not None:
        flags |= int(recv_only)
        return flags, "SNIFF+RECV_ONLY"
    # WinDivert's SNIFF flag already copies matching packets instead of
    # diverting/blocking them.  pydivert 2.1.0 wraps WinDivert 1.x, whose
    # public Flag enum predates RECV_ONLY; never calling send() keeps this
    # handle passive.
    return flags, "SNIFF"


def _tune_windivert_queue(pydivert, handle) -> str:
    """Best-effort queue tuning for both old and new WinDivert drivers."""
    settings = (
        ("QUEUE_LEN", 8192, "长度"),
        ("QUEUE_TIME", 2048, "时间"),
        ("QUEUE_SIZE", 32 * 1024 * 1024, "容量"),
    )
    applied = []
    unsupported = []
    for attribute, value, label in settings:
        parameter = getattr(pydivert.Param, attribute, None)
        if parameter is None:
            unsupported.append(label)
            continue
        try:
            handle.set_param(parameter, value)
            applied.append(label)
        except (OSError, ValueError):
            # Older WinDivert drivers do not support QUEUE_SIZE and another
            # application's already-loaded driver may be older than the DLL
            # bundled by pydivert. Driver defaults remain valid for capture.
            unsupported.append(label)
    if unsupported:
        _print_line(
            "warning",
            "当前 WinDivert 驱动不接受部分队列调优，已保留驱动默认值"
            f" | 不支持={','.join(unsupported)}",
        )
    return ",".join(applied) if applied else "驱动默认"


def _is_admin() -> bool:
    """Whether the current process holds Administrator privileges."""
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _windivert_watchdog(observer: PacketObserver, holder: dict) -> None:
    """Detect a silently-stalled WinDivert capture handle and force a rebuild.

    WinDivert's WFP capture handle can silently stop delivering packets after
    long uptime or reconnect churn; recv() then blocks forever without error.
    The watchdog watches the packet counter and, when no traffic has arrived
    for WATCHDOG_STALL_SECONDS, closes the shared capture handle from this
    thread to interrupt the blocked recv() and drive the capture loop to
    rebuild the handle.
    """
    stall_seconds = int(getattr(core.ctx.options, "rf4_capture_watchdog_seconds", 0) or 0) or 45
    while True:
        last_total = getattr(observer, "total_packets", 0)
        time.sleep(stall_seconds)
        if getattr(observer, "total_packets", 0) != last_total:
            continue
        _print_line(
            "warning",
            f"WinDivert 长时间无数据（{stall_seconds}s），疑似抓包句柄失效，正在重建",
        )
        handle = holder.get("handle")
        if handle is not None:
            try:
                if handle.is_open:
                    handle.close()
            except Exception:
                pass


def _run_windivert_capture(args, observer: PacketObserver, *, default_port: int) -> int:
    try:
        import pydivert
    except ImportError as exc:
        raise RuntimeError(
            "缺少 pydivert，请重新运行 安装依赖.bat 或执行 pip install pydivert"
        ) from exc

    if args.capture_interface:
        _print_line("warning", "WinDivert 在 WFP Network 层抓取本机流量，将忽略 --capture-interface")
    realtime_port = args.capture_port or 0
    realtime_host = str(args.capture_host or "")
    packet_filter = _windivert_filter(realtime_host, realtime_port)
    flags, read_mode = _windivert_read_flags(pydivert)

    _print_line(
        "status",
        "RF4 Monitor 被动抓包模式 | 后端=WinDivert/WFP只读嗅探"
        f" | 模式={read_mode} | realtime={'自动识别 token 握手' if not realtime_port else (realtime_host or '*') + ':' + str(realtime_port)}"
        f" | 输出={'详细' if args.details else ('仅自己来鱼/入护' if args.events_only else '仅自己钓组')}"
        f" | 解析队列={args.capture_queue_size}",
    )
    _print_line(
        "status",
        "请保持本窗口运行，然后启动或重新登录游戏；程序将自动识别 realtime 连接",
    )

    # 看门狗：WinDivert 的 WFP 抓包句柄在长时间运行/重连后可能静默失效，
    # recv() 永久阻塞不再返回。用独立线程定期核对包计数，长时间无新包时
    # 关闭句柄以中断 recv，驱动 recv 循环重建抓包句柄自愈。
    holder: dict = {}
    watchdog = threading.Thread(
        target=_windivert_watchdog,
        args=(observer, holder),
        name="rf4-windivert-watchdog",
        daemon=True,
    )
    watchdog.start()

    attempt = 0
    while True:
        attempt += 1
        try:
            handle = pydivert.WinDivert(packet_filter, flags=flags)
            handle.open()
            holder["handle"] = handle
            queue_mode = _tune_windivert_queue(pydivert, handle)
            dispatcher = PacketDispatcher(observer, args.capture_queue_size)
            _print_line(
                "status",
                f"WinDivert 抓包已打开 | 驱动队列={queue_mode} | 尝试#{attempt}",
            )
        except (OSError, RuntimeError) as exc:
            _print_line(
                "error",
                f"无法打开 WinDivert：{type(exc).__name__}: {exc}"
                + ("；请以管理员身份运行并重新执行 安装依赖.bat" if not _is_admin() else ""),
            )
            return 2
        try:
            while True:
                # pydivert 2.1.0's iterator calls recv() with a 1500-byte default
                # buffer.  Request the full IPv4 packet range explicitly so large
                # TCP segments/offloaded packets are never truncated here.
                packet = handle.recv(65575)
                captured = _windivert_packet_to_capture(packet)
                if captured is not None:
                    dispatcher.submit(captured)
        except KeyboardInterrupt:
            _print_line("status", "抓包已停止")
            return 0
        except Exception as exc:
            _print_line("error", f"WinDivert 抓包通道已断开：{type(exc).__name__}: {exc}；准备重建")
        finally:
            holder.pop("handle", None)
            try:
                if handle.is_open:
                    handle.close()
            except Exception:
                pass
        _print_line("status", f"重新打开 WinDivert 抓包句柄 | 尝试#{attempt + 1}")


def run_capture(args, *, default_port: int = 0) -> int:
    if args.no_color:
        os.environ["NO_COLOR"] = "1"
    if args.list_interfaces:
        return list_interfaces()
    realtime_port = args.capture_port or 0
    bridge = core.RF4ChatBridge()
    try:
        bridge._profile = core.get_profile(args.profile)
    except (KeyError, ValueError) as exc:
        _print_line("error", f"无法加载协议 profile {args.profile!r}：{exc}")
        return 2
    observer = PacketObserver(
        realtime_port=realtime_port,
        realtime_host=args.capture_host,
        bridge=bridge,
    )

    requested_backend = getattr(args, "capture_backend", "auto")
    # 默认优先 Npcap：Npcap 走 NDIS 层，不经过 WFP，避免与火绒/加速器/NetFilter
    # 等多 WFP 驱动冲突导致 WinDivert 长跑后静默失效。仅当显式要求 windivert，
    # 或 Npcap 后端不可用时才回退 WinDivert。
    if requested_backend == "windivert":
        if sys.platform != "win32":
            _print_line("error", "WinDivert 后端仅支持 Windows")
            return 2
        try:
            return _run_windivert_capture(args, observer, default_port=default_port)
        except (OSError, RuntimeError) as exc:
            _print_line("error", f"无法启动 WinDivert：{exc}")
            _print_line("warning", "请以管理员身份运行，并重新执行 安装依赖.bat")
            return 2

    try:
        from scapy.all import conf, sniff
    except ImportError:
        if requested_backend == "auto":
            _print_line("warning", "缺少 scapy，将回退 WinDivert 后端")
            if sys.platform == "win32":
                try:
                    return _run_windivert_capture(args, observer, default_port=default_port)
                except (OSError, RuntimeError) as exc:
                    _print_line("error", f"无法启动 WinDivert：{exc}")
                    return 2
        _print_line("error", "缺少 scapy，请先运行安装依赖.bat 或 pip install -r requirements.txt")
        return 2


    if sys.platform == "win32":
        # Npcap/libpcap is more reliable than Scapy's native Windows sockets for
        # high-rate bidirectional TCP capture.  A larger receive buffer absorbs
        # bursts while the parser thread formats output.
        conf.use_pcap = True
        conf.bufsize = max(
            int(getattr(conf, "bufsize", 0) or 0),
            int(args.capture_buffer_mb) * 1024 * 1024,
        )
        # Surface kernel-side Npcap drops so real capture losses are visible.
        _install_pcap_stats_hook()
        PcapDropMonitor.instance().start()

    selected_interfaces = None
    if args.pcap_file:
        source = f"离线文件={args.pcap_file}"
    else:
        try:
            selected_interfaces, interface_label = _select_live_interfaces(args.capture_interface)
        except Exception as exc:
            _print_line("error", f"无法选择抓包接口：{exc}")
            return 2
        source = f"接口={interface_label}"
    if realtime_port:
        target = f"{args.capture_host or '*'}:{realtime_port}（手动限制）"
    else:
        hint = f"，参考端口 {default_port}" if default_port else ""
        target = f"自动识别 token 握手{hint}"
    if args.details:
        output_mode = "详细输出"
    elif args.events_only:
        output_mode = "仅自己来鱼/入护"
    else:
        output_mode = "仅自己钓组"
    capture_mode = (
        f"可靠模式/缓冲={args.capture_buffer_mb}MB/"
        f"{'混杂' if args.capture_promiscuous else '非混杂'}"
    )
    _print_line(
        "status",
        f"RF4 Monitor 被动抓包模式 | {source} | realtime={target}"
        f" | 抓包={capture_mode} | 输出={output_mode}",
    )
    if not args.pcap_file:
        _print_line("status", "请保持本窗口运行，然后启动或重新登录游戏；程序将自动识别 realtime 连接")

    if realtime_port:
        packet_filter = f"tcp port {realtime_port}"
    elif args.capture_host:
        host_terms = [value.strip() for value in str(args.capture_host).replace(",", ";").split(";") if value.strip()]
        # 游戏 realtime 服务器会负载均衡到多个 IP，硬编码 host 过滤会漏掉未在
        # 列表中的新服务器。内核层抓所有 TCP，交由用户态按协议特征识别。
        packet_filter = "tcp" if host_terms else "tcp"
    else:
        packet_filter = "tcp"

    if (
        not args.pcap_file
        and sys.platform == "win32"
    ):
        # 使用原生 Npcap 读取路径（真实内核缓冲 + 原始以太网帧解析），避免
        # Scapy sniff 的整包构造开销和无效的 conf.bufsize。若 Npcap 初始化
        # 失败则回退 Scapy sniff（兼容 Npcap 未启用 WinPcap API 的情况）。
        try:
            return _run_npcap_raw_capture(
                observer=observer,
                initial_interfaces=selected_interfaces,
                packet_filter=packet_filter,
                queue_size=args.capture_queue_size,
                buffer_mb=args.capture_buffer_mb,
            )
        except Exception as exc:
            _print_line(
                "warning",
                f"Npcap 原生抓包不可用，回退 Scapy sniff | 原因={exc}",
            )

    dispatcher = None
    packet_handler = observer.handle_packet
    if not args.pcap_file:
        dispatcher = PacketDispatcher(observer, args.capture_queue_size)
        packet_handler = dispatcher.submit
    sniff_kwargs = {
        "prn": packet_handler,
        "store": False,
    }
    if args.pcap_file:
        pcap_path = Path(args.pcap_file).expanduser()
        if not pcap_path.is_file():
            _print_line("error", f"抓包文件不存在：{pcap_path}")
            return 2
        sniff_kwargs["offline"] = str(pcap_path)
    else:
        sniff_kwargs["iface"] = selected_interfaces
        sniff_kwargs["filter"] = packet_filter
        sniff_kwargs["promisc"] = args.capture_promiscuous

    try:
        try:
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            if "filter" not in sniff_kwargs:
                raise
            _print_line("warning", f"内核过滤器不可用，将退回用户态流量识别：{exc}")
            sniff_kwargs.pop("filter", None)
            sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        _print_line("status", "抓包已停止")
        return 0
    except Exception as exc:
        _print_line("error", f"无法启动抓包：{exc}")
        if sys.platform == "win32":
            _print_line("warning", "Windows 需要安装 Npcap（启用 WinPcap API 兼容模式），并建议以管理员身份运行")
        else:
            _print_line("warning", "请确认当前用户具备抓包权限，或以管理员/root 权限运行")
        return 2
    _print_line("status", f"抓包处理完成 | 仍活动会话={len(observer.sessions)}")
    return 0


def bounded_int(*, minimum: int, maximum: int):
    def parse(value: str) -> int:
        parsed = int(value)
        if not (minimum <= parsed <= maximum):
            raise argparse.ArgumentTypeError(f"expected {minimum}..{maximum}, got {value}")
        return parsed

    return parse


def _load_capture_config() -> dict:
    """Read rf4_config.json next to the package for passive-mode defaults."""
    try:
        import json

        from . import data_root

        candidates = (
            data_root() / "rf4_config.json",
            data_root() / "rf4_monitor.json",
        )
        for path in candidates:
            if path.is_file():
                data = json.loads(path.read_text("utf-8"))
                if isinstance(data, dict):
                    return data
    except (OSError, ValueError):
        pass
    return {}


def parse_passive_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    import argparse

    config = _load_capture_config()
    capture = config.get("capture", {}) if isinstance(config, dict) else {}

    def cfg(key: str, default):
        value = capture.get(key, default)
        return value if value not in (None, "") else default

    parser = argparse.ArgumentParser(
        prog="rf4_monitor --mode passive",
        description="RF4 Monitor passive packet-capture mode: read the plaintext realtime token and decrypt traffic without proxying the game.",
    )
    parser.add_argument(
        "--capture-interface",
        default=cfg("interface", ""),
        help="Capture interface name. Defaults to automatic selection.",
    )
    parser.add_argument(
        "--capture-backend",
        choices=("npcap", "windivert", "auto"),
        default=cfg("backend", "auto"),
        help="Windows live-capture backend: auto/npcap prefer Npcap (NDIS, avoids WFP conflicts), windivert forces WinDivert.",
    )
    parser.add_argument(
        "--capture-host",
        default=cfg("host", ""),
        help="Optional realtime server IP filter.",
    )
    parser.add_argument(
        "--capture-port",
        type=bounded_int(minimum=0, maximum=65535),
        default=0,
        help="Optional realtime TCP port restriction.",
    )
    parser.add_argument(
        "--capture-buffer-mb",
        type=bounded_int(minimum=1, maximum=256),
        default=int(cfg("buffer_mb", 64) or 64),
        help="Npcap receive-buffer target in MiB. Defaults to 64.",
    )
    parser.add_argument(
        "--capture-queue-size",
        type=bounded_int(minimum=1024, maximum=262144),
        default=int(cfg("queue_size", 32768) or 32768),
        help="Maximum packets queued between capture and protocol parsing. Defaults to 32768.",
    )
    parser.add_argument(
        "--capture-promiscuous",
        action="store_true",
        help="Enable promiscuous capture.",
    )
    parser.add_argument(
        "--pcap-file",
        default="",
        help="Read packets from a pcap/pcapng file instead of capturing a live interface.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List packet-capture interfaces and exit.",
    )
    parser.add_argument("--profile", default="4.0.24799", help="RF4 protocol profile name.")
    parser.add_argument(
        "--events-only",
        action="store_true",
        help="Only show your incoming/kept fish events; hide fishing-gear process telemetry.",
    )
    parser.add_argument(
        "--details",
        "--detailed-output",
        dest="details",
        action="store_true",
        help="Show public catches, player state, chat, feeding, and other readable details.",
    )
    parser.add_argument(
        "--telemetry-categories",
        default="all",
        help="Comma-separated telemetry categories: all, fish, player, feed, chat, room, session, unknown.",
    )
    parser.add_argument("--room-details", action="store_true", help="Show low-level room-message details.")
    parser.add_argument("--low-level", action="store_true", help="Show lower-confidence business telemetry.")
    parser.add_argument("--unknown", action="store_true", help="Show unrecognized frame summaries.")
    parser.add_argument("--plain-frames", action="store_true", help="Show decrypted frame hex/ascii details.")
    parser.add_argument("--verbose", action="store_true", help="Show capture and parser diagnostics.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    parser.add_argument(
        "--set",
        action="append",
        dest="set_options",
        default=[],
        metavar="key=value",
        help="Set an addon option (e.g. --set rf4_verbose_logging=true) for passive parsing.",
    )
    parser.add_argument(
        "--reference-path",
        action="append",
        dest="reference_paths",
        help="File or directory used to extract RF4 realtime hosts/port.",
    )
    parser.add_argument(
        "--include-all-domains",
        action="store_true",
        help="Do not filter extracted domains to RF4-owned suffixes.",
    )
    args, unknown = parser.parse_known_args(argv)
    if capture.get("auto_detect_dynamic_port", False):
        args.capture_port = 0
    elif args.capture_port == 0:
        args.capture_port = int(cfg("port", 0) or 0)
    return args, unknown


def _apply_set_options(options, set_options: list[str]) -> None:
    for item in set_options or ():
        if "=" not in item:
            continue
        key, _, raw_value = item.partition("=")
        key = key.strip()
        value = raw_value.strip()
        current = getattr(options, key, None)
        if isinstance(current, bool):
            setattr(options, key, value.lower() in {"1", "true", "yes", "on"})
        elif isinstance(current, int):
            try:
                setattr(options, key, int(value))
            except ValueError:
                pass
        else:
            setattr(options, key, value)


def run_passive(argv: list[str] | None = None) -> int:
    """Passive-mode entry: parse capture args, load reference defaults, run capture."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args, _passthrough = parse_passive_args(raw_argv)
    _open_sniffer_log()

    default_port = 0
    if getattr(args, "reference_paths", None):
        try:
            from .launcher import extract_reference_info

            reference = extract_reference_info(
                [Path(value).expanduser() for value in args.reference_paths],
                include_all_domains=args.include_all_domains,
            )
            default_port = reference.realtime_port or 0
        except Exception:
            default_port = 0

    _install_passive_context(args)
    _apply_set_options(core.ctx.options, args.set_options)
    _bridge_mod.ctx = core.ctx
    return run_capture(args, default_port=default_port)
