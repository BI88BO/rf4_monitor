"""RF4 旁路监听引擎（纯只读）。

不劫持、不改 hosts、不伪造证书、不监听端口。通过 Npcap Packet.dll 被动抓取
游戏 realtime TCP 流，从 auth 包提取 token，RC4 解密业务帧，复用 RF4ChatBridge
的解析/描述/浮窗广播逻辑输出。零改包风险。

用法（引擎模式，由 rf4_entry.py 以 RF4_SNIFFER_MODE=1 启动）：
    python -m rf4_core.passive_engine
"""
from __future__ import annotations

import os
import signal
import sys
import threading
import time
from types import SimpleNamespace
from typing import Dict, List, Optional, Tuple

from .bridge import RF4ChatBridge, FlowSession
from .protocol import RC4Stream, take_complete_frames, try_parse_auth_packet
from .sniffer_core import (
    AdapterHandle,
    TcpSegment,
    enumerate_adapters,
    packet_available,
    parse_packet,
)
from .tcp_reassembly import TcpFlowState, TcpStreamAssembler

DEFAULT_REALTIME_PORTS = (9442, 9569)


class FakeFlow:
    def __init__(self, flow_id: str) -> None:
        self.id = flow_id


class PassiveEngine:
    def __init__(self, options=None) -> None:
        self._bridge = RF4ChatBridge()
        self._options = options if options is not None else {}
        self._running = False
        self._assembler = TcpStreamAssembler(target_ports=DEFAULT_REALTIME_PORTS)
        self._sessions: Dict[str, FlowSession] = {}

    # ------------------------------------------------------------------
    # 配置与启动
    # ------------------------------------------------------------------
    def _apply_options(self) -> None:
        # 让 bridge 的 ctx.options 指向我们的选项（含浮窗广播开关）。
        # 旁路监听为纯只读：强制关闭任何游戏内注入，杜绝改包。
        import rf4_core.bridge as bridge_mod

        merged = dict(self._options)
        merged["rf4_enable_self_chat_injection"] = False
        opts = SimpleNamespace()
        for key, value in merged.items():
            setattr(opts, key, value)
        bridge_mod.ctx.options = opts
        try:
            self._bridge.configure(set())
        except Exception:
            pass

    def run(self) -> int:
        if not packet_available():
            print("错误：Npcap/Packet.dll 不可用，无法旁路抓包。请安装 Npcap 后重试。", file=sys.stderr)
            return 2
        self._apply_options()
        adapters = enumerate_adapters()
        if not adapters:
            print("错误：未找到可用网卡。", file=sys.stderr)
            return 2
        selected = self._pick_adapters(adapters)
        if not selected:
            print("错误：未找到适合抓包的网卡。", file=sys.stderr)
            return 2
        print(f"[rf4-sniffer] 监听网卡: {', '.join(selected)}")
        print(f"[rf4-sniffer] 目标端口: {DEFAULT_REALTIME_PORTS}")
        self._running = True
        try:
            self._capture_loop(selected)
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            print(f"[rf4-sniffer] 抓包失败: {exc}", file=sys.stderr)
            return 1
        return 0

    def _pick_adapters(self, adapters: List[str]) -> List[str]:
        # 同时抓 Npcap Loopback（游戏走 127.0.0.1:9442）和第一个真实网卡
        # （游戏直连真实服务器时出站流量），保证两种路径都覆盖。
        selected: List[str] = []
        loopback = next((a for a in adapters if "Loopback" in a), None)
        if loopback:
            selected.append(loopback)
        real = [a for a in adapters if "Loopback" not in a]
        if real:
            selected.append(real[0])
        return selected

    def _capture_loop(self, adapter_names: List[str]) -> None:
        handles = [AdapterHandle(name) for name in adapter_names]
        try:
            while self._running:
                got = False
                for handle in handles:
                    pkt = handle.read_packet()
                    if pkt is None:
                        continue
                    got = True
                    try:
                        seg = parse_packet(pkt)
                    except Exception:
                        continue
                    if seg is None:
                        continue
                    self._handle_segment(seg)
                if not got:
                    time.sleep(0.005)
        finally:
            for handle in handles:
                try:
                    handle.close()
                except Exception:
                    pass

    def _handle_segment(self, seg: TcpSegment) -> None:
        flow = self._assembler.feed(
            seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port, seg.payload
        )
        if flow is None:
            return
        if flow.authenticated:
            self._process_flow(flow)

    # ------------------------------------------------------------------
    # 业务处理（复用 bridge）
    # ------------------------------------------------------------------
    def _process_flow(self, flow: TcpFlowState) -> None:
        key = f"{flow.key[0]}:{flow.key[1]}-{flow.key[2]}:{flow.key[3]}"
        session = self._sessions.get(key)
        if session is None:
            session = FlowSession(profile=self._bridge._profile)
            session.token = flow.token
            session.auth_seen = True
            session.uuid_seen = True
            session.hermes_seen = True
            session.client_read_rc4 = RC4Stream(flow.token.encode("utf-8"))
            session.server_read_rc4 = RC4Stream(flow.token.encode("utf-8"))
            self._sessions[key] = session

        # 服务器方向（S->C）：来鱼/装备/商店推送
        if flow.server_raw:
            rc4 = session.server_read_rc4
            self._decode_buffer(session, rc4, flow.server_raw, from_client=False, flow_id=key)
            flow.server_raw.clear()
        # 客户端方向（C->S）：请求
        if flow.client_raw:
            rc4 = session.client_read_rc4
            self._decode_buffer(session, rc4, flow.client_raw, from_client=True, flow_id=key)
            flow.client_raw.clear()

    def _decode_buffer(
        self,
        session: FlowSession,
        rc4: RC4Stream,
        buffer: bytearray,
        *,
        from_client: bool,
        flow_id: str,
    ) -> None:
        frames = take_complete_frames(buffer)
        if not frames:
            return
        fake_flow = FakeFlow(flow_id)
        for frame in frames:
            if frame.frame_type == 1:
                continue
            if not frame.payload:
                continue
            try:
                plain_body = rc4.crypt(frame.payload)
            except Exception:
                continue
            try:
                self._bridge._maybe_log_telemetry_frame(fake_flow, session, from_client, plain_body)
            except Exception:
                pass
            if not from_client:
                try:
                    self._bridge._handle_server_frame(session, plain_body)
                except Exception:
                    pass
            else:
                try:
                    self._bridge._track_rpc_request_command(session, plain_body)
                    self._bridge._track_building_rpc_request(session, plain_body)
                except Exception:
                    pass

    def stop(self) -> None:
        self._running = False


def _parse_set_args(argv: List[str]) -> Dict[str, object]:
    """解析 --set key=value 参数（与 mitmdump 风格一致）。"""
    options: Dict[str, object] = {}
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--set" and index + 1 < len(argv):
            pair = argv[index + 1]
            index += 2
            if "=" in pair:
                key, value = pair.split("=", 1)
                options[key.strip()] = _coerce_option(value.strip())
        else:
            index += 1
    return options


def _coerce_option(value: str) -> object:
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    options = _parse_set_args(args)
    engine = PassiveEngine(options=options)
    return engine.run()


if __name__ == "__main__":
    raise SystemExit(main())
