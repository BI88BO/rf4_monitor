"""TCP 流重组 + RF4 realtime 认证识别。

旁路抓包得到的是一堆 TCP 段，需要按 (src,dst,port) 四元组重组为逻辑 TCP 流，
并识别 RF4 realtime 的 auth 包（客户端首包，\\x01\\x00/\\x01\\x01 + u32 + token），
提取 token 供后续 RC4 解密使用。

不做端口过滤（realtime 端口动态变化，如 9442/9569/9448...），而是用 auth
包特征识别 RF4 流。只有能成功认证（提取到 token）的流才会被业务层处理。

本模块只做重组与认证识别，不负责 RC4 解密（解密与取帧在 passive_engine 复用
现有 bridge 逻辑）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .protocol import try_parse_auth_packet


@dataclass
class TcpFlowState:
    """一个 TCP 连接的重组状态。"""
    key: Tuple[str, int, str, int]
    # 客户端方向缓冲（auth 包已消费，剩余为未解密业务载荷）
    client_raw: bytearray = field(default_factory=bytearray)
    # 服务器方向缓冲（未解密业务载荷）
    server_raw: bytearray = field(default_factory=bytearray)
    direction_locked: bool = False
    client_endpoint: Optional[Tuple[str, int]] = None
    token: Optional[str] = None
    authenticated: bool = False
    auth_consumed: bool = False


MAX_FLOW_BUFFER = 256 * 1024


def flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, int, str, int]:
    return (src_ip, src_port, dst_ip, dst_port)


class TcpStreamAssembler:
    """把 TCP 段重组成流，识别 RF4 realtime 认证。

    不限定端口；auth 特征识别 RF4 流。非 RF4 流保持未认证，靠 max_flows
    与单流缓冲上限控制内存。sniffer 中途接入的已建立流可能错过 auth，
    无法解密（该连接跳过）；游戏重连会开新连接并再次发出 auth 包。
    """

    def __init__(self, max_flows: int = 512) -> None:
        self._flows: Dict[Tuple[str, int, str, int], TcpFlowState] = {}
        self._max_flows = max_flows

    @staticmethod
    def _reverse_key(key: Tuple[str, int, str, int]) -> Tuple[str, int, str, int]:
        src_ip, src_port, dst_ip, dst_port = key
        return (dst_ip, dst_port, src_ip, src_port)

    def _prune(self) -> None:
        if len(self._flows) <= self._max_flows:
            return
        # 丢弃缓冲最小（最可能已结束或非 RF4）的未认证流。
        candidates = sorted(
            self._flows.items(),
            key=lambda kv: (
                0 if kv[1].authenticated else 1,
                len(kv[1].client_raw) + len(kv[1].server_raw),
            ),
        )
        for key, _flow in candidates[: len(self._flows) - self._max_flows]:
            self._flows.pop(key, None)

    def feed(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
    ) -> Optional[TcpFlowState]:
        """投递一个 TCP 段载荷，返回所属流。"""
        if not payload:
            return None

        key = flow_key(src_ip, src_port, dst_ip, dst_port)
        flow = self._flows.get(key)
        if flow is None:
            rev = self._reverse_key(key)
            flow = self._flows.get(rev)
            if flow is not None:
                # 反向流量：服务器方向
                if len(flow.server_raw) < MAX_FLOW_BUFFER:
                    flow.server_raw.extend(payload)
                return flow
            flow = TcpFlowState(key=key)
            self._flows[key] = flow

        if not flow.direction_locked:
            flow.direction_locked = True
            flow.client_endpoint = (src_ip, src_port)
        is_client = flow.client_endpoint == (src_ip, src_port)
        if is_client:
            if len(flow.client_raw) < MAX_FLOW_BUFFER:
                flow.client_raw.extend(payload)
            if not flow.auth_consumed:
                self._maybe_authenticate(flow)
        else:
            if len(flow.server_raw) < MAX_FLOW_BUFFER:
                flow.server_raw.extend(payload)
        self._prune()
        return flow

    def _maybe_authenticate(self, flow: TcpFlowState) -> None:
        if flow.authenticated or not flow.client_raw:
            return
        parsed = try_parse_auth_packet(bytes(flow.client_raw))
        if parsed is None:
            return
        token, consumed = parsed
        flow.token = token
        flow.authenticated = True
        flow.auth_consumed = True
        del flow.client_raw[:consumed]

    def flows(self) -> List[TcpFlowState]:
        return list(self._flows.values())

    def reset(self) -> None:
        self._flows.clear()
