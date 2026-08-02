"""Npcap Packet.dll 封装：被动抓取本机 TCP 流量。

纯只读抓包，不劫持、不改包、不注入。用于 RF4 旁路监听模式。
依赖：Npcap 驱动（服务名 npcap），通过 Packet.dll（System32）访问。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    _packet_dll = ctypes.WinDLL("Packet.dll")
except OSError:
    _packet_dll = None

DEFAULT_SNAPLEN = 65536
DEFAULT_READ_TIMEOUT_MS = 200
DEFAULT_BUFFER_SIZE = 512 * 1024


def packet_available() -> bool:
    return _packet_dll is not None


# ---------------------------------------------------------------------------
# Packet.dll 函数签名
# ---------------------------------------------------------------------------
def _setup_packet_api() -> None:
    if _packet_dll is None:
        return
    p = _packet_dll
    p.PacketGetAdapterNames.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulong)]
    p.PacketGetAdapterNames.restype = ctypes.c_int
    p.PacketOpenAdapter.argtypes = [ctypes.c_char_p]
    p.PacketOpenAdapter.restype = ctypes.c_void_p
    p.PacketCloseAdapter.argtypes = [ctypes.c_void_p]
    p.PacketCloseAdapter.restype = ctypes.c_int
    p.PacketSetBuff.argtypes = [ctypes.c_void_p, ctypes.c_int]
    p.PacketSetBuff.restype = ctypes.c_int
    p.PacketSetReadTimeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
    p.PacketSetReadTimeout.restype = ctypes.c_int
    p.PacketAllocatePacket.argtypes = []
    p.PacketAllocatePacket.restype = ctypes.c_void_p
    p.PacketInitPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    p.PacketInitPacket.restype = ctypes.c_int
    p.PacketReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    p.PacketReceivePacket.restype = ctypes.c_int
    p.PacketFreePacket.argtypes = [ctypes.c_void_p]
    p.PacketFreePacket.restype = None


_setup_packet_api()


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_ulonglong),
        ("InternalHigh", ctypes.c_ulonglong),
        ("Offset", ctypes.c_ulong),
        ("OffsetHigh", ctypes.c_ulong),
        ("hEvent", ctypes.c_void_p),
    ]


class _PacketStruct(ctypes.Structure):
    """对应 Packet32.h 的 PACKET 结构（64 位）。"""
    _fields_ = [
        ("hEvent", ctypes.c_void_p),
        ("Overlapped", _Overlapped),
        ("Buf", ctypes.c_void_p),
        ("Length", ctypes.c_ulong),
        ("ulBytesReceived", ctypes.c_ulong),
        ("bIoComplete", ctypes.c_byte),
    ]


def enumerate_adapters() -> List[str]:
    """枚举可用网卡，返回适配器名列表（\\Device\\NPF_...）。"""
    return [name for name, _desc in enumerate_adapters_with_desc()]


def enumerate_adapters_with_desc() -> List[Tuple[str, str]]:
    """枚举可用网卡，返回 (适配器名, 描述) 列表。

    描述用于识别真实联网网卡（如 Intel Wireless / Realtek GbE），
    避免选中 WAN Miniport / 虚拟网卡等抓不到业务流量的适配器。
    """
    if _packet_dll is None:
        return []
    buf = ctypes.create_string_buffer(65536)
    buf_len = ctypes.c_ulong(65536)
    ret = _packet_dll.PacketGetAdapterNames(buf, ctypes.byref(buf_len))
    if not ret:
        return []
    data = buf.raw[: buf_len.value]
    parts = data.split(b"\x00")
    names: List[str] = []
    descs: List[str] = []
    for part in parts:
        if not part:
            continue
        try:
            text = part.decode("utf-8", errors="replace")
        except Exception:
            continue
        if text.startswith("\\Device\\NPF_"):
            names.append(text)
        elif text and not text.startswith("\\Device\\"):
            descs.append(text)
    # PacketGetAdapterNames 顺序：先全部名字，再全部描述。
    pairs: List[Tuple[str, str]] = []
    for index, name in enumerate(names):
        desc = descs[index] if index < len(descs) else ""
        pairs.append((name, desc))
    return pairs


@dataclass
class LinkPacket:
    """一个完整链路层帧。"""
    timestamp_us: int
    raw: bytes

    @property
    def eth_type(self) -> int:
        if len(self.raw) < 14:
            return 0
        return int.from_bytes(self.raw[12:14], "big")


@dataclass
class TcpSegment:
    """解析后的 TCP 段。"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    payload: bytes
    flags: int


class SnifferError(RuntimeError):
    pass


class AdapterHandle:
    """封装一个打开的 Npcap 适配器。"""

    def __init__(self, adapter_name: str) -> None:
        if _packet_dll is None:
            raise SnifferError("Packet.dll 不可用，请确认已安装 Npcap")
        self._name = adapter_name
        self._handle = _packet_dll.PacketOpenAdapter(adapter_name.encode("ascii"))
        if not self._handle:
            raise SnifferError(f"无法打开网卡 {adapter_name}")
        _packet_dll.PacketSetBuff(self._handle, DEFAULT_BUFFER_SIZE)
        _packet_dll.PacketSetReadTimeout(self._handle, DEFAULT_READ_TIMEOUT_MS)
        raw_packet = _packet_dll.PacketAllocatePacket()
        if not raw_packet:
            self.close()
            raise SnifferError("无法分配抓包缓冲")
        self._packet = ctypes.cast(raw_packet, ctypes.POINTER(_PacketStruct))

    @property
    def name(self) -> str:
        return self._name

    def read_packet(self) -> Optional[LinkPacket]:
        """读取一个链路层帧。无包可读时返回 None。"""
        if _packet_dll is None or not self._handle:
            return None
        buf = ctypes.create_string_buffer(DEFAULT_SNAPLEN)
        _packet_dll.PacketInitPacket(self._packet, ctypes.cast(buf, ctypes.c_void_p), DEFAULT_SNAPLEN)
        ok = _packet_dll.PacketReceivePacket(self._handle, self._packet, 1)
        if not ok:
            return None
        length = int(self._packet.contents.ulBytesReceived)
        if length <= 0 or length > len(buf.raw):
            return None
        raw = bytes(buf.raw[:length])
        import time as _time
        return LinkPacket(timestamp_us=int(_time.time() * 1_000_000), raw=raw)

    def close(self) -> None:
        if _packet_dll is None:
            return
        if self._packet:
            try:
                _packet_dll.PacketFreePacket(self._packet)
            except Exception:
                pass
            self._packet = None
        if self._handle:
            try:
                _packet_dll.PacketCloseAdapter(self._handle)
            except Exception:
                pass
            self._handle = None

    def __enter__(self) -> "AdapterHandle":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def parse_eth_frame(pkt: LinkPacket) -> Optional[Tuple[int, str, str, bytes]]:
    """解析以太网帧，返回 (ether_type, src_mac, dst_mac, payload)。支持 vlan。"""
    raw = pkt.raw
    if len(raw) < 14:
        return None
    dst_mac = raw[0:6].hex()
    src_mac = raw[6:12].hex()
    eth_type = int.from_bytes(raw[12:14], "big")
    offset = 14
    if eth_type == 0x8100:  # 802.1Q vlan
        if len(raw) < 18:
            return None
        eth_type = int.from_bytes(raw[16:18], "big")
        offset = 18
    return eth_type, src_mac, dst_mac, raw[offset:]


def _ip_to_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def parse_ip_packet(payload: bytes) -> Optional[Tuple[int, str, str, bytes, bytes]]:
    """解析 IPv4 包，返回 (protocol, src_ip, dst_ip, header_tail, tcp_payload)。"""
    if len(payload) < 20:
        return None
    version_ihl = payload[0]
    if (version_ihl >> 4) != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if len(payload) < ihl + 4:
        return None
    protocol = payload[9]
    src_ip = _ip_to_str(payload[12:16])
    dst_ip = _ip_to_str(payload[16:20])
    return protocol, src_ip, dst_ip, payload[ihl:], payload


def parse_tcp_segment(payload: bytes) -> Optional[TcpSegment]:
    """解析 TCP 段。payload 是 IP 层之后的数据。"""
    if len(payload) < 20:
        return None
    src_port = int.from_bytes(payload[0:2], "big")
    dst_port = int.from_bytes(payload[2:4], "big")
    seq = int.from_bytes(payload[4:8], "big")
    data_offset = (payload[12] >> 4) * 4
    flags = payload[13]
    if len(payload) < data_offset:
        return None
    tcp_payload = payload[data_offset:]
    return TcpSegment(
        src_ip="",
        dst_ip="",
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        payload=tcp_payload,
        flags=flags,
    )


def _find_ipv4_offset(raw: bytes, start: int = 20) -> Optional[int]:
    """在帧中扫描 IPv4 头起始偏移。

    Npcap 伪头长度随网卡类型变化（loopback 24 字节；WLAN 等 32 字节），
    直接扫描找到首个可信的 IPv4 头（version=4 且 IHL 在 5..15），最稳健。
    """
    for pos in range(start, len(raw) - 4):
        first = raw[pos]
        if (first >> 4) != 4:
            continue
        ihl = (first & 0x0F) * 4
        if ihl < 20 or ihl > 60:
            continue
        total_len = int.from_bytes(raw[pos + 2:pos + 4], "big")
        if total_len < ihl or total_len > 4096:
            continue
        # 协议字段 6=TCP 或 17=UDP，且源/目的 IP 非全 0
        protocol = raw[pos + 9]
        if protocol not in (6, 17):
            continue
        return pos
    return None


def parse_packet(pkt: LinkPacket) -> Optional[TcpSegment]:
    """把链路层帧解析成 TCP 段。

    支持标准以太网帧与多种 Npcap 伪头（loopback 24 字节、WLAN 等更长），
    通过扫描定位 IPv4 头，不依赖固定偏移。
    """
    raw = pkt.raw
    ip_offset = _find_ipv4_offset(raw)
    if ip_offset is None:
        return None
    ip_payload = raw[ip_offset:]
    parsed_ip = parse_ip_packet(ip_payload)
    if parsed_ip is None:
        return None
    protocol, src_ip, dst_ip, tcp_payload, _ip_rest = parsed_ip
    if protocol != 6:  # TCP
        return None
    seg = parse_tcp_segment(tcp_payload)
    if seg is None:
        return None
    seg.src_ip = src_ip
    seg.dst_ip = dst_ip
    return seg
