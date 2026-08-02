"""TCP 流重组 + RF4 realtime 认证识别。

旁路抓包得到的是一堆 TCP 段，需要按 (src,dst,port) 四元组重组为逻辑 TCP 流，
并识别 RF4 realtime 的 auth 包（客户端首包，\\x01\\x00/\\x01\\x01 + u32 + token），
提取 token 供后续 RC4 解密使用。

不做端口过滤（realtime 端口动态变化），而是用 auth 包特征识别 RF4 流。
旁路抓包可能先抓到服务器->客户端方向，因此不假设"先到的方向是客户端"：
对双向缓冲都尝试 auth 识别，命中 auth 的一边即客户端。

本模块只做重组与认证识别，不负责 RC4 解密。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .protocol import try_parse_auth_packet


@dataclass
class TcpFlowState:
    """一个 TCP 连接的重组状态。"""
    key: Tuple[str, int, str, int]
    # 端点 A / B（方向未定，见 client_endpoint）
    endpoint_a: Optional[Tuple[str, int]] = None
    endpoint_b: Optional[Tuple[str, int]] = None
    # 客户端方向缓冲（auth 包已消费，剩余为未解密业务载荷）
    client_raw: bytearray = field(default_factory=bytearray)
    # 服务器方向缓冲（未解密业务载荷）
    server_raw: bytearray = field(default_factory=bytearray)
    # auth 命中后记录真正的客户端端点
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
    与单流缓冲上限控制内存。
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
                self._feed_direction(flow, (src_ip, src_port), (dst_ip, dst_port), payload)
                return flow
            flow = TcpFlowState(key=key, endpoint_a=(src_ip, src_port), endpoint_b=(dst_ip, dst_port))
            self._flows[key] = flow

        self._feed_direction(flow, (src_ip, src_port), (dst_ip, dst_port), payload)
        self._prune()
        return flow

    def _feed_direction(
        self,
        flow: TcpFlowState,
        src_ep: Tuple[str, int],
        dst_ep: Tuple[str, int],
        payload: bytes,
    ) -> None:
        # 认证后方向已确定：按 client_endpoint 判断
        if flow.authenticated and flow.client_endpoint is not None:
            if src_ep == flow.client_endpoint:
                if len(flow.client_raw) < MAX_FLOW_BUFFER:
                    flow.client_raw.extend(payload)
            else:
                if len(flow.server_raw) < MAX_FLOW_BUFFER:
                    flow.server_raw.extend(payload)
            return
        # 认证前：不假设方向，存到两侧缓冲，后续双向尝试 auth
        is_a = src_ep == flow.endpoint_a
        is_b = src_ep == flow.endpoint_b
        if is_a and not is_b:
            if len(flow.client_raw) < MAX_FLOW_BUFFER:
                flow.client_raw.extend(payload)
        elif is_b and not is_a:
            if len(flow.server_raw) < MAX_FLOW_BUFFER:
                flow.server_raw.extend(payload)
        else:
            if len(flow.client_raw) < MAX_FLOW_BUFFER:
                flow.client_raw.extend(payload)

        if not flow.authenticated:
            self._maybe_authenticate(flow)

    def _maybe_authenticate(self, flow: TcpFlowState) -> None:
        if flow.authenticated:
            return
        # 尝试 client_raw（方向 A->B 或未知）是否为 auth
        client_parsed = try_parse_auth_packet(bytes(flow.client_raw)) if flow.client_raw else None
        server_parsed = try_parse_auth_packet(bytes(flow.server_raw)) if flow.server_raw else None

        if client_parsed is not None:
            token, consumed = client_parsed
            flow.token = token
            flow.authenticated = True
            flow.auth_consumed = True
            # client_raw 是客户端方向
            flow.client_endpoint = flow.endpoint_a if flow.endpoint_a else None
            del flow.client_raw[:consumed]
            return
        if server_parsed is not None:
            token, consumed = server_parsed
            flow.token = token
            flow.authenticated = True
            flow.auth_consumed = True
            # server_raw 实际是客户端方向（方向 B->A 是客户端发的 auth）
            flow.client_endpoint = flow.endpoint_b if flow.endpoint_b else None
            # 把 server_raw 搬到 client_raw（它是真正的客户端方向）
            flow.client_raw = flow.server_raw
            flow.server_raw = bytearray()
            del flow.client_raw[:consumed]

    def flows(self) -> List[TcpFlowState]:
        return list(self._flows.values())

    def reset(self) -> None:
        self._flows.clear()
