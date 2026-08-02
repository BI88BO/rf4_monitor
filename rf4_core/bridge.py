import json
import math
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


class BoundedDict(dict):
    """容量有界的 dict：超过上限后淘汰最早插入的条目，防止长时间运行内存无限增长。"""

    def __init__(self, max_size: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._max_size = max_size
        while len(self) > self._max_size:
            self.pop(next(iter(self)))

    def __setitem__(self, key, value) -> None:
        super().__setitem__(key, value)
        while len(self) > self._max_size:
            self.pop(next(iter(self)))


class BoundedSet(set):
    """容量有界的 set：超过上限后淘汰部分条目，防止长时间运行内存无限增长。"""

    def __init__(self, max_size: int, iterable: Iterable = ()) -> None:
        super().__init__(iterable)
        self._max_size = max_size
        while len(self) > self._max_size:
            self.discard(next(iter(self)))

    def add(self, value) -> None:
        super().add(value)
        while len(self) > self._max_size:
            self.discard(next(iter(self)))

from . import console
from .fish_labels import load_fish_labels
from .launcher import parse_https_upstream_map, rewrite_login_logon_info
from .protocol import (
    BusinessPayloadSummary,
    CatchSummary,
    FishSetupMeta,
    KeepFishRequest,
    RC4Stream,
    RF4ProtocolProfile,
    RoomBroadcast,
    RoomDetailItem,
    RpcEnvelope,
    ascii_strings,
    build_ack_frame,
    build_frame,
    build_room_ack_response_body,
    build_room_message_push_body,
    extract_catch_summary_from_response,
    get_profile,
    guid_le,
    parse_contact_left,
    parse_envelope,
    parse_fish_setup_push,
    parse_fishing_gear_and_setup,
    parse_keep_fish_request,
    parse_public_chat_request,
    parse_release_fish_request,
    parse_room_ack_request,
    parse_room_ack_response,
    parse_room_broadcast,
    read_arg_header,
    read_marked_string,
    take_complete_frames,
    try_parse_auth_packet,
    try_parse_first_frame,
    try_parse_uuid_packet,
    u32,
)

try:
    from mitmproxy import ctx, http, tcp
except Exception:
    from types import SimpleNamespace
    ctx = SimpleNamespace(
        options=SimpleNamespace(),
        log=SimpleNamespace(info=lambda *_args, **_kwargs: None),
        master=SimpleNamespace(commands=SimpleNamespace(call=lambda *_args, **_kwargs: None)),
    )
    http = SimpleNamespace(HTTPFlow=object)
    tcp = SimpleNamespace(TCPFlow=object)

_colorize_console_text = console._colorize_console_text

@dataclass
class SyntheticChatEvent:
    event_id: int
    fish_key: str
    weight_raw: int
    location_id: str
    users_count: int
    phase: str = "kept"
    sender_name: str = "【我自己】"
    line_type: int = 3
    fishing_gear_id: str = ""
    gear_slot_text: str = ""


@dataclass
class FlowSession:
    profile: RF4ProtocolProfile
    token: Optional[str] = None
    auth_seen: bool = False
    uuid_seen: bool = False
    hermes_seen: bool = False
    client_buffer: bytearray = field(default_factory=bytearray)
    server_buffer: bytearray = field(default_factory=bytearray)
    passthrough: bool = False
    client_read_rc4: Optional[RC4Stream] = None
    client_write_rc4: Optional[RC4Stream] = None
    server_read_rc4: Optional[RC4Stream] = None
    server_write_rc4: Optional[RC4Stream] = None
    fish_setup_cache: Dict[str, FishSetupMeta] = field(default_factory=lambda: BoundedDict(1024))
    keep_requests: Dict[int, KeepFishRequest] = field(default_factory=lambda: BoundedDict(128))
    room_events: Dict[int, RoomBroadcast] = field(default_factory=lambda: BoundedDict(512))
    room_ack_calls: Dict[int, int] = field(default_factory=lambda: BoundedDict(128))
    synthetic_events: Dict[int, SyntheticChatEvent] = field(default_factory=lambda: BoundedDict(64))
    synthetic_wire_ids: set[int] = field(default_factory=lambda: BoundedSet(64))
    announced_fish_setup_ids: set[str] = field(default_factory=lambda: BoundedSet(256))
    latest_location_id: Optional[str] = None
    latest_users_count: Optional[int] = None
    gear_slots: Dict[str, int] = field(default_factory=dict)
    next_gear_slot: int = 1
    next_synthetic_event_id: int = 0x71000000
    next_synthetic_call_id: int = 0x61000000
    next_synthetic_wire_id: int = 0x100000

    def handshake_complete(self) -> bool:
        return self.auth_seen and self.uuid_seen and self.hermes_seen

    def ensure_rc4(self) -> None:
        if not self.token:
            raise ValueError("cannot initialize RC4 without token")
        if self.client_read_rc4 is None:
            key = self.token.encode("utf-8")
            self.client_read_rc4 = RC4Stream(key)
            self.client_write_rc4 = RC4Stream(key)
            self.server_read_rc4 = RC4Stream(key)
            self.server_write_rc4 = RC4Stream(key)

    def build_client_forward_frame(self, frame_type: int, wire_id: int, plain_body: bytes) -> bytes:
        if not self.server_write_rc4:
            raise ValueError("server write RC4 stream is not initialized")
        return build_frame(frame_type, wire_id, self.server_write_rc4.crypt(plain_body))

    def alloc_event_id(self) -> int:
        value = self.next_synthetic_event_id
        self.next_synthetic_event_id += 1
        return value

    def alloc_call_id(self) -> int:
        value = self.next_synthetic_call_id
        self.next_synthetic_call_id += 1
        return value

    def alloc_wire_id(self) -> int:
        value = self.next_synthetic_wire_id
        self.next_synthetic_wire_id += 1
        return value

    def build_server_injection(self, plain_body: bytes) -> bytes:
        if not self.client_write_rc4:
            raise ValueError("client write RC4 stream is not initialized")
        wire_id = self.alloc_wire_id()
        self.synthetic_wire_ids.add(wire_id)
        encrypted = self.client_write_rc4.crypt(plain_body)
        return build_frame(0, wire_id, encrypted)

    def build_server_forward_frame(self, frame_type: int, wire_id: int, plain_body: bytes) -> bytes:
        if not self.client_write_rc4:
            raise ValueError("client write RC4 stream is not initialized")
        return build_frame(frame_type, wire_id, self.client_write_rc4.crypt(plain_body))


class RF4ChatBridge:
    SELF_EVENT_PHASE_INCOMING = "incoming"
    SELF_EVENT_PHASE_BITTEN = "bitten"
    SELF_EVENT_PHASE_KEPT = "kept"
    SELF_EVENT_PHASE_ESCAPED = "escaped"
    SELF_EVENT_PHASE_RELEASED = "released"
    TELEMETRY_CATEGORY_LABELS = {
        "fish": "钓鱼",
        "player": "人物",
        "feed": "投喂",
        "chat": "聊天",
        "room": "房间",
        "session": "会话",
        "unknown": "未知",
    }
    SESSION_COMMAND_LABELS = {
        7: "设置语言",
        8: "反作弊报告",
        9: "反作弊标志",
        15: "进入地图",
        18: "硬件/区域信息",
    }
    PLAYER_COMMAND_LABELS = {
        8: "训练状态",
        9: "人物坐标",
        10: "船只使用",
        11: "篝火操作",
        12: "落水状态",
        13: "厨房进食",
        14: "钓具辅助",
        15: "纺车辅助",
        16: "领奖",
        17: "鱼获奖杯",
        18: "警告列表",
        19: "已读警告",
        20: "改名",
        21: "改地区",
        22: "读取邮箱",
        23: "设置邮箱",
        24: "验证邮箱",
        25: "提交封禁信息",
        26: "封禁信息",
        27: "弹吉他",
    }
    SERVER_PLAYER_COMMAND_LABELS = {
        1: "下发玩家资料",
        2: "下发玩家状态",
        6: "下发技能信息",
        8: "下发成就信息",
    }
    FISHING_COMMAND_LABELS = {
        1: "准备抛竿",
        2: "抛竿",
        3: "落点/实钩上下文",
        4: "结束钓鱼",
        5: "入护请求",
        6: "放生鱼",
        7: "钓鱼过程位置上报",
        8: "搏鱼拉力",
        9: "拉线动作",
        10: "请求鱼讯",
        11: "进入搏鱼阶段",
        12: "接触/脱离",
        14: "来鱼信息",
        15: "鱼同步",
    }
    FEEDING_COMMAND_LABELS = {
        1: "打窝/投喂",
    }
    DEFAULT_FISH_LABELS_ZH = {
        "a.sleeper": "葛氏鲈塘鳢",
        "a_smelt": "亚洲胡瓜鱼",
        "barsch": "俄罗斯梭吻鲈",
        "c.carp": "金鲫",
        "c_bleak": "欧鲌",
        "c_nase": "大鼻软口鱼",
        "c.roach": "常见拟鲤",
        "crucian": "银鲫",
        "dace": "雅罗鱼",
        "e.chub": "诸子鲦",
        "osetr_ship": "裸腹鲟",
        "perch": "鲈鱼",
        "ripus": "拉多加白鲑",
        "ruffe": "梅花鲈",
        "ruffe_n": "长吻梅花鲈",
        "s.bream": "银鲷鱼",
        "s.orfe": "圆腹雅罗鱼",
        "tench": "丁鱥",
    }
    GRADE_LABELS_BY_LINE_TYPE = {
        26: "蓝",
    }
    RECORD_CLASS_LABELS = {
        "BL": "底钓",
        "DEF": "常规",
        "L": "轻",
        "PICKER": "Picker",
        "SEA": "海钓",
        "TL": "手竿",
        "UL": "超轻",
    }

    def __init__(self) -> None:
        self._profile = get_profile("4.0.24799")
        self._sessions: Dict[str, FlowSession] = {}
        self._latest_realtime_hosts: tuple[str, ...] = ()
        self._latest_realtime_port: Optional[int] = None
        self._fish_labels_zh = dict(self.DEFAULT_FISH_LABELS_ZH)
        try:
            self._fish_labels_zh.update(load_fish_labels(self._profile.name))
        except Exception:
            pass

    def load(self, loader) -> None:
        loader.add_option("rf4_enable_chat_bridge", bool, True, "Enable RF4 catch-to-chat injection.")
        loader.add_option("rf4_enable_login_rewrite", bool, True, "Rewrite RF4 login logon realtime host/port to the local listener.")
        loader.add_option(
            "rf4_https_upstream_map",
            str,
            "",
            "Domain=IP map used to keep reverse HTTPS upstream traffic off the local hosts redirect.",
        )
        loader.add_option("rf4_profile", str, "4.0.24799", "RF4 protocol profile name.")
        loader.add_option("rf4_realtime_redirect_host", str, "127.0.0.1", "Realtime host written into the RF4 login logon response.")
        loader.add_option("rf4_realtime_redirect_port", int, 0, "Realtime port written into the RF4 login logon response.")
        loader.add_option("rf4_sender_name", str, "RF4Chat", "Sender name used in synthetic 24/19 responses.")
        loader.add_option("rf4_avatar_url", str, "", "Optional avatar URL for synthetic 24/19 responses.")
        loader.add_option("rf4_sender_level", int, 1, "Sender level used in synthetic 24/19 responses.")
        loader.add_option("rf4_sender_region", int, 1, "Sender region/status field used in synthetic 24/19 responses.")
        loader.add_option("rf4_sender_class", int, 0, "Sender class/icon field used in synthetic 24/19 responses.")
        loader.add_option("rf4_sender_badge", int, 0, "Sender badge/flags field used in synthetic 24/19 responses.")
        loader.add_option("rf4_default_location_id", str, "", "Fallback location id for synthetic 24/27 messages.")
        loader.add_option("rf4_default_users_count", int, 0, "Fallback users count for synthetic 24/27 messages.")
        loader.add_option(
            "rf4_enable_self_chat_injection",
            bool,
            False,
            "Inject self incoming/kept fish messages into the in-game chat stream.",
        )
        loader.add_option("rf4_log_parsed_events", bool, True, "Print parsed fishing/chat events to the mitm console.")
        loader.add_option("rf4_log_telemetry", bool, True, "Print compact RF4 business telemetry summaries.")
        loader.add_option(
            "rf4_log_room_protocol_details",
            bool,
            False,
            "Print low-level 24/19 room-message lookup request/response details.",
        )
        loader.add_option(
            "rf4_log_low_level_telemetry",
            bool,
            False,
            "Print lower-confidence server state pushes and generic protocol summaries.",
        )
        loader.add_option(
            "rf4_log_unknown_telemetry",
            bool,
            False,
            "Also print compact summaries for unrecognized RF4 RPC frames.",
        )
        loader.add_option(
            "rf4_telemetry_categories",
            str,
            "all",
            "Telemetry categories to print: all, fish, player, feed, chat, room, session, unknown. Comma-separated.",
        )
        loader.add_option("rf4_log_plain_frames", bool, False, "Log every decrypted RF4 business frame with hex/ascii details.")
        loader.add_option("rf4_verbose_logging", bool, False, "Log per-session handshake and injection details.")
        loader.add_option(
            "rf4_event_bridge_host",
            str,
            "127.0.0.1",
            "UDP host used to broadcast fish incoming/kept events to an external overlay.",
        )
        loader.add_option(
            "rf4_event_bridge_port",
            int,
            0,
            "UDP port used to broadcast fish incoming/kept events. 0 disables the event bridge.",
        )
        loader.add_option("rf4_show_incoming", bool, True, "Show self fish incoming events (来鱼).")
        loader.add_option("rf4_show_bitten", bool, True, "Show self fish bitten events (确认咬钩).")
        loader.add_option("rf4_show_kept", bool, True, "Show self fish kept events (入护).")
        loader.add_option("rf4_show_escaped", bool, True, "Show self fish escaped events (脱钩).")
        loader.add_option("rf4_show_released", bool, True, "Show self fish released events (放生).")
        loader.add_option("rf4_show_fish", bool, True, "Show fish telemetry logs (搏鱼/来鱼过程).")
        loader.add_option("rf4_show_player", bool, True, "Show player telemetry logs (坐标/状态).")
        loader.add_option("rf4_show_feed", bool, True, "Show feed telemetry logs (打窝/投喂).")
        loader.add_option("rf4_show_chat", bool, True, "Show chat telemetry logs (公共聊天/频道鱼获).")
        loader.add_option("rf4_show_room", bool, True, "Show room telemetry logs (房间消息).")
        loader.add_option("rf4_show_session", bool, True, "Show session telemetry logs (会话信息).")
        loader.add_option("rf4_show_unknown", bool, True, "Show unknown telemetry logs (未知协议).")
        loader.add_option("rf4_show_catch_broadcast", bool, True, "Show other players' catch broadcasts in overlay (频道鱼获).")
        loader.add_option("rf4_show_chat_broadcast", bool, True, "Show public chat in overlay (公共聊天).")

    def configure(self, updated) -> None:
        self._profile = get_profile(ctx.options.rf4_profile)
        self._fish_labels_zh = dict(self.DEFAULT_FISH_LABELS_ZH)
        try:
            self._fish_labels_zh.update(load_fish_labels(self._profile.name))
        except Exception:
            pass

    def server_connect(self, data) -> None:
        if data.server.address is None:
            return

        original_host, original_port = data.server.address
        upstream_map = parse_https_upstream_map(ctx.options.rf4_https_upstream_map)
        connect_host = upstream_map.get(original_host.lower())
        if connect_host:
            data.server.address = (connect_host, original_port)
            data.server.sni = original_host
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"rewrote HTTPS upstream {original_host}:{original_port} -> "
                    f"{connect_host}:{original_port}"
                )
            return

        realtime_target = self._select_realtime_upstream(original_port)
        if realtime_target is None:
            return

        realtime_host, realtime_port = realtime_target
        if (original_host, original_port) == realtime_target:
            return

        data.server.address = realtime_target
        if ctx.options.rf4_verbose_logging:
            self._log(
                f"rewrote realtime upstream {original_host}:{original_port} -> "
                f"{realtime_host}:{realtime_port}"
            )

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        self._sessions[flow.id] = FlowSession(profile=self._profile)

    def tcp_end(self, flow: tcp.TCPFlow) -> None:
        self._sessions.pop(flow.id, None)

    def tcp_error(self, flow: tcp.TCPFlow) -> None:
        self._sessions.pop(flow.id, None)

    MAX_FLOW_MESSAGES = 2000
    TRIM_FLOW_MESSAGES_KEEP = 1000
    MAX_SESSIONS = 512

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        if not ctx.options.rf4_enable_chat_bridge:
            return
        try:
            session = self._sessions.setdefault(flow.id, FlowSession(profile=self._profile))
            if len(self._sessions) > self.MAX_SESSIONS:
                # 清理长期未回收的死会话，防止大量短连接累积泄漏。
                for dead_id in [key for key in self._sessions if key != flow.id][: len(self._sessions) - self.MAX_SESSIONS]:
                    self._sessions.pop(dead_id, None)
            message = flow.messages[-1]
            if message.from_client:
                message.content = self._process_client_bytes(flow, session, message.content)
            else:
                message.content = self._process_server_bytes(flow, session, message.content)
            # 长时间运行时 mitmproxy 会保留整条 TCP 连接的每条消息，导致内存随游戏时长无限增长。
            # 只保留最近的消息用于处理，旧消息由我们的会话缓冲自行消费，无需留在 flow 里。
            if len(flow.messages) > self.MAX_FLOW_MESSAGES:
                del flow.messages[: len(flow.messages) - self.TRIM_FLOW_MESSAGES_KEEP]
        except Exception as exc:
            # 任何异常都不能逃逸出 addon，否则会中断整个代理连接并导致游戏断线。
            if ctx.options.rf4_verbose_logging:
                self._log(f"tcp_message error flow={flow.id}: {exc}")
            return

    def request(self, flow: http.HTTPFlow) -> None:
        if not ctx.options.rf4_verbose_logging:
            return
        if not self._is_login_request(flow):
            return
        self._log_http_message(
            "login request plaintext",
            f"{flow.request.method} {flow.request.pretty_host}{flow.request.path}",
            flow.request.headers,
            self._extract_message_text(flow.request),
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return

        is_login_request = self._is_login_request(flow)
        response_text = self._extract_message_text(flow.response)
        if ctx.options.rf4_verbose_logging and is_login_request:
            self._log_http_message(
                "login response plaintext",
                f"HTTP {flow.response.status_code} {flow.request.pretty_host}{flow.request.path}",
                flow.response.headers,
                response_text,
            )

        if not ctx.options.rf4_enable_login_rewrite:
            return
        redirect_port = int(ctx.options.rf4_realtime_redirect_port or 0)
        if redirect_port <= 0:
            return

        text = response_text
        if "<logon" not in text or "<host>" not in text or "<port>" not in text:
            if ctx.options.rf4_verbose_logging and is_login_request:
                self._log(
                    "login response did not contain <logon>; "
                    f"preview={self._quote_text(text, limit=200)}"
                )
            return

        rewrite = rewrite_login_logon_info(
            text,
            redirect_host=ctx.options.rf4_realtime_redirect_host,
            redirect_port=redirect_port,
            repeat_host_count=True,
        )
        if rewrite is None:
            if ctx.options.rf4_verbose_logging:
                self._log("login response matched <logon>, but rewrite_login_logon_info returned no result")
            return
        if rewrite.text == text:
            if ctx.options.rf4_verbose_logging:
                self._log("login response already matched the configured realtime redirect target")
            return

        self._latest_realtime_hosts = rewrite.original.hosts
        self._latest_realtime_port = rewrite.original.port
        flow.response.set_text(rewrite.text)
        self._log(
            "rewrote login realtime target "
            f"{';'.join(rewrite.original.hosts)}:{rewrite.original.port} -> "
            f"{';'.join(rewrite.redirected_hosts)}:{rewrite.redirected_port}"
        )
        if ctx.options.rf4_verbose_logging and is_login_request:
            self._log_http_message(
                "login response rewritten plaintext",
                f"HTTP {flow.response.status_code} {flow.request.pretty_host}{flow.request.path}",
                flow.response.headers,
                rewrite.text,
            )

    def _safe_log(self, text: str) -> None:
        """写日志，绝不让终端编码(如 GBK 无法输出非 ASCII)异常逃逸到上层。

        日志只是旁路观测，任何编码问题都不能中断正在转发的连接/请求，
        否则会导致 RC4 流失步、HTTP 改写中断，进而触发游戏断线重连。
        """
        try:
            ctx.log.info(text)
        except Exception:
            try:
                # 降级：丢弃 GBK 无法表示的字符(如阿拉伯/西里尔字符)，保证不再次抛异常
                safe = text.encode("gbk", errors="ignore").decode("gbk", errors="ignore")
                ctx.log.info(safe)
            except Exception:
                try:
                    ctx.log.info(text.encode("ascii", errors="ignore").decode("ascii"))
                except Exception:
                    pass

    def _log(self, text: str) -> None:
        self._safe_log(f"[rf4-monitor] {text}")

    def _log_event(self, text: str) -> None:
        if ctx.options.rf4_log_parsed_events:
            self._safe_log(text)

    def _log_self_event(self, text: str) -> None:
        if not ctx.options.rf4_log_parsed_events:
            return
        self._safe_log(_colorize_console_text(text, "96"))

    def _log_telemetry(self, category: str, text: str) -> None:
        if not self._telemetry_enabled(category):
            return
        self._safe_log(text)

    @staticmethod
    def _telemetry_enabled(category: str) -> bool:
        if not bool(getattr(ctx.options, "rf4_log_telemetry", True)):
            return False
        # 日志始终全量输出，不受显示设置勾选影响。
        category = category.lower()
        raw_categories = str(getattr(ctx.options, "rf4_telemetry_categories", "all") or "all")
        categories = {item.strip().lower() for item in raw_categories.split(",") if item.strip()}
        if not categories or "all" in categories or "*" in categories:
            return True
        if "none" in categories or "off" in categories or "false" in categories:
            return False
        return category in categories

    @staticmethod
    def _self_chat_injection_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_enable_self_chat_injection", False))

    @staticmethod
    def _room_protocol_details_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_log_room_protocol_details", False))

    @staticmethod
    def _low_level_telemetry_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_log_low_level_telemetry", False))

    def _select_realtime_upstream(self, original_port: int) -> Optional[tuple[str, int]]:
        if not self._latest_realtime_hosts or self._latest_realtime_port is None:
            return None
        # 登录返回的真实 realtime 端口可能与本机监听端口(reverse:tcp 上游)不一致，
        # 不能要求端口严格相等，否则动态 host 改写永远不会生效。
        if original_port != self._latest_realtime_port:
            redirect_port = int(getattr(ctx.options, "rf4_realtime_redirect_port", 0) or 0)
            if redirect_port > 0 and original_port != redirect_port:
                return None
        return self._latest_realtime_hosts[0], self._latest_realtime_port

    @staticmethod
    def _is_login_request(flow: http.HTTPFlow) -> bool:
        request = flow.request
        if request is None:
            return False
        host = request.pretty_host.lower()
        path = request.path.lower()
        if host != "api.rf4game.ru":
            return False
        return path.startswith("/login.php") or path.startswith("/steam.php")

    MAX_HANDSHAKE_BUFFER = 1 << 20

    def _process_client_bytes(self, flow: tcp.TCPFlow, session: FlowSession, chunk: bytes) -> bytes:
        if session.passthrough:
            return chunk
        session.client_buffer.extend(chunk)
        out = bytearray()

        if not session.auth_seen:
            if len(session.client_buffer) >= 2:
                # \x01\x00 和 \x01\x01 都是 RF4 realtime 认证包开头（后者是打开钓鱼站后
                # 游戏重连 realtime 使用的格式），其余开头才可能是商店等非 RF4 连接。
                if bytes(session.client_buffer[:2]) not in (b"\x01\x00", b"\x01\x01"):
                    self._log(
                        f"client non-RF4 data flow={flow.id} "
                        f"first_bytes={session.client_buffer[:2].hex()} "
                        f"len={len(session.client_buffer)} "
                        f"hex={self._hex_preview(bytes(session.client_buffer), limit=256)}; "
                        f"entering passthrough"
                    )
                    session.passthrough = True
                    accumulated = bytes(session.client_buffer)
                    session.client_buffer.clear()
                    return accumulated
            else:
                # 数据不足 2 字节，先缓冲等待更多数据。
                return b""
            parsed = try_parse_auth_packet(bytes(session.client_buffer))
            if parsed is None:
                if len(session.client_buffer) > self.MAX_HANDSHAKE_BUFFER:
                    # 数据不符合 RF4 认证包格式，进入透传模式（原样转发），
                    # 避免把非认证连接（如商店的额外 realtime 连接）的数据吞掉。
                    self._log(
                        f"client handshake timeout flow={flow.id} "
                        f"len={len(session.client_buffer)}; entering passthrough"
                    )
                    session.passthrough = True
                    session.client_buffer.clear()
                    return chunk
                return b""
            token, consumed = parsed
            session.token = token
            session.auth_seen = True
            # 立即用 token 初始化 RC4：正常连接在 Hermes 后初始化，但 Hermes 是明文
            # 不消耗 keystream，所以提前初始化不影响 keystream 位置。
            try:
                session.ensure_rc4()
            except Exception:
                pass
            out.extend(session.client_buffer[:consumed])
            del session.client_buffer[:consumed]
            if ctx.options.rf4_verbose_logging:
                masked = token[:24] + "..." if len(token) > 24 else token
                self._log(f"captured auth token for flow {flow.id}: {masked}")

        if session.auth_seen and not session.hermes_seen:
            frame = try_parse_first_frame(bytes(session.client_buffer))
            if frame is None:
                if len(session.client_buffer) > self.MAX_HANDSHAKE_BUFFER:
                    self._log(
                        f"client hermes buffer overflow flow={flow.id} "
                        f"len={len(session.client_buffer)}; entering passthrough"
                    )
                    session.passthrough = True
                    session.client_buffer.clear()
                    return chunk
                return bytes(out)
            if b"<hermes>" not in frame.payload:
                # 打开钓鱼站等场景下，游戏可能跳过 Hermes 明文帧直接进入 RC4 加密业务。
                # 用全新的 RC4(位置0)克隆做校验，不推进会话流；校验通过则继续正常解析。
                if session.token:
                    try:
                        probe = RC4Stream(session.token.encode("utf-8"))
                        probed = probe.crypt(frame.payload)
                        if parse_envelope(probed) is not None:
                            self._log(
                                f"client skipped-hermes business frame flow={flow.id} "
                                f"wire={frame.wire_id}; continuing parsing"
                            )
                            session.hermes_seen = True
                            if session.client_buffer:
                                out.extend(self._process_app_frames(flow, session, from_client=True))
                            return bytes(out)
                    except Exception:
                        pass
                # 解密失败或非业务帧，进入透传。
                self._log(
                    f"client non-hermes frame after auth flow={flow.id} "
                    f"frame_type={frame.frame_type} wire={frame.wire_id} "
                    f"payload_hex={self._hex_preview(frame.payload, limit=64)}; entering passthrough"
                )
                session.passthrough = True
                buffered = bytes(session.client_buffer)
                session.client_buffer.clear()
                return bytes(out) + buffered
            out.extend(frame.raw)
            del session.client_buffer[:len(frame.raw)]
            session.hermes_seen = True
            session.ensure_rc4()
            if ctx.options.rf4_verbose_logging:
                self._log(f"Hermes handshake completed for flow {flow.id}")

        if session.handshake_complete() and session.client_buffer:
            out.extend(self._process_app_frames(flow, session, from_client=True))

        return bytes(out)

    def _process_server_bytes(self, flow: tcp.TCPFlow, session: FlowSession, chunk: bytes) -> bytes:
        if session.passthrough:
            # 记录透传连接服务器首包特征，判断是否误判了 realtime 连接。
            if not session.server_buffer:
                self._log(
                    f"passthrough server first data flow={flow.id} "
                    f"first={chunk[:16].hex()} ascii={self._format_ascii_strings(chunk, limit=2)}"
                )
                session.server_buffer.extend(b"seen")
            return chunk
        session.server_buffer.extend(chunk)
        out = bytearray()

        if not session.uuid_seen:
            parsed = try_parse_uuid_packet(bytes(session.server_buffer))
            if parsed is None:
                if len(session.server_buffer) > self.MAX_HANDSHAKE_BUFFER:
                    self._log(
                        f"server handshake buffer overflow flow={flow.id} "
                        f"len={len(session.server_buffer)}; entering passthrough"
                    )
                    session.passthrough = True
                    session.server_buffer.clear()
                    return chunk
                return b""
            _, consumed = parsed
            session.uuid_seen = True
            out.extend(session.server_buffer[:consumed])
            del session.server_buffer[:consumed]
            if ctx.options.rf4_verbose_logging:
                self._log(f"captured UUID handshake packet for flow {flow.id}")

        if session.handshake_complete() and session.server_buffer:
            out.extend(self._process_app_frames(flow, session, from_client=False))

        return bytes(out)

    def _process_app_frames(self, flow: tcp.TCPFlow, session: FlowSession, from_client: bool) -> bytes:
        buffer = session.client_buffer if from_client else session.server_buffer
        frames = take_complete_frames(buffer)
        if not frames:
            return b""

        out = bytearray()
        read_cipher = session.client_read_rc4 if from_client else session.server_read_rc4
        if read_cipher is None:
            raise ValueError("RC4 stream is not initialized")

        for frame in frames:
            if frame.frame_type == 1:
                if from_client and frame.wire_id in session.synthetic_wire_ids:
                    session.synthetic_wire_ids.discard(frame.wire_id)
                    if ctx.options.rf4_verbose_logging:
                        self._log(f"swallowed client transport ack for synthetic wire {frame.wire_id} flow {flow.id}")
                    continue
                out.extend(frame.raw)
                continue
            if not frame.payload:
                out.extend(frame.raw)
                continue

            plain_body = read_cipher.crypt(frame.payload)
            try:
                self._maybe_log_telemetry_frame(flow, session, from_client, plain_body)
            except Exception:
                pass
            if getattr(ctx.options, "rf4_log_plain_frames", False):
                self._log(
                    f"app {'C->S' if from_client else 'S->C'} "
                    f"flow={flow.id} frame_type={frame.frame_type} wire={frame.wire_id} "
                    f"body_len={len(plain_body)} {self._describe_plain_body(plain_body)}"
                )
            if from_client:
                try:
                    plain_forward, injections = self._handle_client_frame(session, plain_body)
                except Exception as exc:
                    # 业务解析异常绝不能中断帧转发，否则 RC4 流失步导致游戏断线/未响应。
                    if ctx.options.rf4_verbose_logging:
                        self._log(f"client frame handler error flow={flow.id}: {exc}")
                    plain_forward, injections = plain_body, []
                if plain_forward is not None:
                    out.extend(session.build_client_forward_frame(frame.frame_type, frame.wire_id, plain_forward))
                for injected in injections:
                    try:
                        ctx.master.commands.call("inject.tcp", flow, True, injected)
                    except Exception as exc:
                        if ctx.options.rf4_verbose_logging:
                            self._log(f"inject.tcp failed flow={flow.id}: {exc}")
            else:
                out.extend(session.build_server_forward_frame(frame.frame_type, frame.wire_id, plain_body))
                try:
                    out.extend(self._handle_server_frame(session, plain_body))
                except Exception as exc:
                    if ctx.options.rf4_verbose_logging:
                        self._log(f"server frame handler error flow={flow.id}: {exc}")

        return bytes(out)

    def _maybe_log_telemetry_frame(
        self,
        flow: tcp.TCPFlow,
        session: FlowSession,
        from_client: bool,
        plain_body: bytes,
    ) -> None:
        if not bool(getattr(ctx.options, "rf4_log_telemetry", True)):
            return
        try:
            telemetry = self._describe_telemetry_frame(session, from_client, plain_body)
            if telemetry is None:
                return
            category, text = telemetry
            self._log_telemetry(category, text)
        except Exception as exc:
            # 日志链路(如终端 GBK 编码无法输出非 ASCII 字符)绝不能中断帧转发，
            # 否则 RC4 流已推进但帧未转发，导致客户端/服务器永久失步后断线。
            if ctx.options.rf4_verbose_logging:
                self._log(f"telemetry log failed flow={flow.id}: {exc}")
            return

    def _describe_telemetry_frame(
        self,
        session: FlowSession,
        from_client: bool,
        plain_body: bytes,
    ) -> Optional[tuple[str, str]]:
        envelope = parse_envelope(plain_body)
        if envelope is None:
            if not bool(getattr(ctx.options, "rf4_log_unknown_telemetry", False)):
                return None
            direction = "C->S" if from_client else "S->C"
            return "unknown", f"{self._format_direction(direction)} 原始包 | 可读文本={self._format_ascii_strings(plain_body, limit=4)}"

        direction = "C->S" if from_client else "S->C"
        kind = "request" if envelope.marker == -1 else "response"
        prefix = self._telemetry_prefix(direction, kind, envelope)

        if from_client:
            keep_request = parse_keep_fish_request(envelope, session.profile)
            if keep_request:
                return (
                    "fish",
                    f"请求把鱼入护 | 钓组={self._short_id(keep_request.fishing_gear_id)} "
                    f"鱼编号={self._short_id(keep_request.fish_setup_id)}",
                )

            public_chat = parse_public_chat_request(envelope, session.profile)
            if public_chat:
                return "chat", f"发送公共聊天 | 内容={self._quote_text(self._clean_text(public_chat.message or ''))}"

            ack_request = parse_room_ack_request(envelope, session.profile)
            if ack_request:
                if self._room_protocol_details_enabled():
                    return "room", f"{prefix} 补全房间消息发送者 | 消息ID={ack_request.event_id}"
                return None

            known = self._describe_known_client_business_telemetry(session, prefix, envelope)
            if known:
                return known

        else:
            fish_setup = parse_fish_setup_push(envelope, session.profile)
            if fish_setup:
                weight = self._format_chat_weight(fish_setup.weight_hint_raw) if fish_setup.weight_hint_raw else "unknown"
                length = f"{fish_setup.length_hint:.3f}" if fish_setup.length_hint is not None else "unknown"
                return (
                    "fish",
                    f"有鱼靠近 | 鱼={self._format_fish_name(fish_setup.fish_key)} "
                    f"鱼名key={fish_setup.fish_key} 预估重量={weight} 长度={length} "
                    f"鱼编号={self._short_id(fish_setup.fish_setup_id)} 钓组={self._short_id(fish_setup.fishing_gear_id)}",
                )

            broadcast = parse_room_broadcast(envelope, session.profile)
            if broadcast:
                if not self._room_protocol_details_enabled():
                    return None
                summary = self._format_room_push_summary(broadcast)
                if summary:
                    return "room", f"{prefix} {summary}"
                return None

            request_event_id = session.room_ack_calls.get(envelope.call_id)
            ack_response = parse_room_ack_response(envelope, session.profile)
            if ack_response:
                if not self._room_protocol_details_enabled():
                    return None
                event_id = ack_response.event_id if ack_response.event_id is not None else request_event_id
                return (
                    "room",
                    f"{prefix} 房间消息发送者已补全 | 消息ID={event_id} "
                    f"玩家={self._quote_text(ack_response.sender_name or '')} 等级={ack_response.sender_rank}",
                )

            keep_request = session.keep_requests.get(envelope.call_id)
            if keep_request and envelope.marker == -2:
                catch = extract_catch_summary_from_response(plain_body)
                fish_key = catch.fish_key
                weight_raw = catch.weight_raw
                if keep_request.fish_setup_id:
                    meta = session.fish_setup_cache.get(keep_request.fish_setup_id)
                    if meta:
                        fish_key = fish_key or meta.fish_key
                        weight_raw = weight_raw or meta.weight_hint_raw
                fish_name = self._format_fish_name(fish_key) if fish_key else "unknown"
                weight = self._format_chat_weight(weight_raw) if weight_raw else "unknown"
                return (
                    "fish",
                    f"入护结果 | 鱼={fish_name} 鱼名key={fish_key or 'unknown'} "
                    f"重量={weight} 规格={catch.size_enum} 鱼编号={self._short_id(keep_request.fish_setup_id)}",
                )

            known = self._describe_known_server_business_telemetry(session, prefix, envelope)
            if known:
                return known

        if not bool(getattr(ctx.options, "rf4_log_unknown_telemetry", False)):
            return None
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            return "unknown", f"{prefix} 未识别业务包 | 可读文本={self._format_ascii_strings(envelope.payload, limit=4)}"
        return "unknown", f"{prefix} 未识别响应包 | 可读文本={self._format_ascii_strings(envelope.payload, limit=4)}"

    def _describe_known_client_business_telemetry(
        self,
        session: FlowSession,
        prefix: str,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if envelope.marker != -1 or envelope.main_cmd is None or envelope.sub_cmd is None:
            return None

        profile = session.profile
        main_cmd = envelope.main_cmd
        sub_cmd = envelope.sub_cmd
        if main_cmd == profile.session_main_cmd:
            label = self.SESSION_COMMAND_LABELS.get(sub_cmd)
            if label:
                return "session", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if main_cmd == profile.player_main_cmd:
            label = self.PLAYER_COMMAND_LABELS.get(sub_cmd)
            if not label:
                return None
            if sub_cmd == 9:
                return "player", self._format_business_line(label, self._format_scene_pose_payload(envelope.payload))
            return "player", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))

        if main_cmd == profile.feeding_main_cmd:
            label = self.FEEDING_COMMAND_LABELS.get(sub_cmd)
            if label:
                return "feed", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if main_cmd != profile.fishing_main_cmd:
            return None

        label = self.FISHING_COMMAND_LABELS.get(sub_cmd)
        if not label:
            return None
        if sub_cmd == profile.fight_step_sub_cmd:
            details = self._format_fish_move_payload(envelope.payload)
        elif sub_cmd == profile.fight_load_sub_cmd:
            details = self._format_fight_load_payload(envelope.payload)
        elif sub_cmd == profile.fight_stage_sub_cmd:
            details = self._format_fight_stage_payload(envelope.payload)
        elif sub_cmd == profile.contact_left_sub_cmd:
            details = self._format_contact_left_payload(envelope.payload)
        else:
            details = self._format_generic_business_payload(envelope.payload)
        return "fish", self._format_business_line(label, details)

    def _describe_known_server_business_telemetry(
        self,
        session: FlowSession,
        prefix: str,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if envelope.marker != -1 or envelope.main_cmd is None or envelope.sub_cmd is None:
            return None

        profile = session.profile
        if envelope.main_cmd == profile.server_player_main_cmd:
            if not self._low_level_telemetry_enabled():
                return None
            label = self.SERVER_PLAYER_COMMAND_LABELS.get(envelope.sub_cmd)
            if label:
                return "player", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if envelope.main_cmd == profile.fishing_main_cmd:
            label = self.FISHING_COMMAND_LABELS.get(envelope.sub_cmd)
            if label:
                return "fish", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
        return None

    @staticmethod
    def _format_business_line(label: str, details: str) -> str:
        if not details:
            return label
        if details.startswith("="):
            return f"{label} {details}"
        return f"{label} | {details}"

    def _format_scene_pose_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        group = self._first_float_group(summary, minimum=4) or self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            return f"={self._format_float_tuple(group[:3])}"
        parts = self._format_summary_tail(summary, include_u32=False, include_float_groups=False)
        return self._join_business_parts(parts, payload)

    def _format_fish_move_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        gear = self._first_guid(summary)
        if gear:
            parts.append(f"钓组={self._short_id(gear)}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"钓组坐标={self._format_float_tuple(group[:3])}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_fight_load_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        gear = self._first_guid(summary)
        if gear:
            parts.append(f"钓组={self._short_id(gear)}")
        group = self._first_float_group(summary, minimum=4)
        if group and len(group) >= 4:
            parts.append(f"拉力方向={self._format_float_tuple((group[0], group[1], group[3]))}")
            parts.append(f"负载={self._format_float(group[2])}")
        elif group and len(group) >= 3:
            parts.append(f"向量={self._format_float_tuple(group[:3])}")
        tick = self._last_u32(summary)
        if tick is not None:
            parts.append(f"序号={tick}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_fight_stage_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        if len(summary.guids) >= 1:
            parts.append(f"钓组={self._short_id(summary.guids[0])}")
        if len(summary.guids) >= 2:
            parts.append(f"鱼编号={self._short_id(summary.guids[1])}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"状态值={self._format_float_tuple(group[:4])}")
        tick = self._last_u32(summary)
        if tick is not None:
            parts.append(f"序号={tick}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_contact_left_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        if len(summary.guids) >= 1:
            parts.append(f"钓组={self._short_id(summary.guids[0])}")
        if len(summary.guids) >= 2:
            parts.append(f"鱼编号={self._short_id(summary.guids[1])}")
        if summary.u32_values:
            parts.append(f"原因/序号={summary.u32_values[0]}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"状态值={self._format_float_tuple(group[:4])}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_generic_business_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts = self._format_arg_prefix(summary)
        parts.extend(self._format_summary_tail(summary))
        return self._join_business_parts(parts, payload)

    def _summarize_business_payload(self, payload: bytes) -> BusinessPayloadSummary:
        arg_count = None
        try:
            arg_count, _ = read_arg_header(payload, 0)
        except (ValueError, IndexError):
            arg_count = None
        strings = self._scan_payload_strings(payload, limit=6)
        guids = self._scan_guid_markers(payload, limit=4)
        u32_values = self._scan_marked_u32_values(payload, limit=6)
        float_groups = self._scan_float_groups(payload, limit=4)
        return BusinessPayloadSummary(
            arg_count=arg_count,
            strings=strings,
            guids=guids,
            u32_values=u32_values,
            float_groups=float_groups,
        )

    def _scan_payload_strings(self, data: bytes, limit: int) -> Tuple[str, ...]:
        values: List[str] = []
        pos = 0
        while len(values) < limit and pos < len(data):
            idx = data.find(b"\x14", pos)
            if idx < 0:
                break
            try:
                value, next_pos = read_marked_string(data, idx)
            except (ValueError, IndexError, UnicodeDecodeError):
                pos = idx + 1
                continue
            if value and self._payload_string_is_interesting(value):
                values.append(self._clean_text(value))
            pos = max(next_pos, idx + 1)

        for value in ascii_strings(data, min_len=8):
            if len(values) >= limit:
                break
            if self._payload_string_is_interesting(value):
                values.append(self._clean_text(value))

        return tuple(self._unique_limited(values, limit))

    @staticmethod
    def _payload_string_is_interesting(value: str) -> bool:
        text = value.strip()
        if not text or text in {"507", "135"}:
            return False
        if "\ufffd" in text:
            return False
        if len(text) <= 2 and text.isascii():
            return False
        if text.isascii() and len(text) < 6 and not any(ch in text for ch in "._[]"):
            return False
        if all(ch.isdigit() or ch in ".-_:/" for ch in text):
            return False
        return True

    @staticmethod
    def _scan_guid_markers(data: bytes, limit: int) -> Tuple[str, ...]:
        values: List[str] = []
        pos = 0
        while len(values) < limit and pos + 17 <= len(data):
            idx = data.find(b"\x0c", pos)
            if idx < 0 or idx + 17 > len(data):
                break
            raw = data[idx + 1:idx + 17]
            if raw != b"\x00" * 16:
                try:
                    value = guid_le(raw)
                except (ValueError, AttributeError):
                    pos = idx + 1
                    continue
                if value not in values:
                    values.append(value)
            pos = idx + 17
        return tuple(values)

    @staticmethod
    def _scan_marked_u32_values(data: bytes, limit: int) -> Tuple[int, ...]:
        values: List[int] = []
        pos = 0
        while len(values) < limit and pos + 5 <= len(data):
            idx = data.find(b"\x10", pos)
            if idx < 0 or idx + 5 > len(data):
                break
            value = u32(data, idx + 1)
            if 0 <= value <= 0x7FFFFFFF and value not in values:
                values.append(value)
            pos = idx + 5
        return tuple(values)

    def _scan_float_groups(self, data: bytes, limit: int) -> Tuple[Tuple[float, ...], ...]:
        groups: List[Tuple[float, ...]] = []
        pos = 0
        while len(groups) < limit and pos + 12 <= len(data):
            group = self._read_float_group_at(data, pos, 4)
            if group is None:
                group = self._read_float_group_at(data, pos, 3)
            if group is None:
                pos += 1
                continue
            if not groups or not self._same_float_group(groups[-1], group):
                groups.append(group)
            pos += len(group) * 4
        return tuple(groups)

    def _read_float_group_at(self, data: bytes, pos: int, count: int) -> Optional[Tuple[float, ...]]:
        if pos + count * 4 > len(data):
            return None
        values = struct.unpack_from("<" + "f" * count, data, pos)
        if not self._usable_float_group(values):
            return None
        return tuple(values)

    @staticmethod
    def _usable_float_group(values: Tuple[float, ...]) -> bool:
        if not values:
            return False
        usable = []
        for value in values:
            if not math.isfinite(value):
                return False
            if abs(value) > 100000.0:
                return False
            if value != 0.0 and abs(value) < 0.000001:
                return False
            usable.append(value)
        if not any(abs(value) >= 0.01 for value in usable):
            return False
        return True

    @staticmethod
    def _same_float_group(left: Tuple[float, ...], right: Tuple[float, ...]) -> bool:
        if len(left) != len(right):
            return False
        return all(abs(a - b) < 0.0001 for a, b in zip(left, right))

    @staticmethod
    def _format_arg_prefix(summary: BusinessPayloadSummary) -> List[str]:
        return [f"参数={summary.arg_count}"] if summary.arg_count is not None else []

    def _format_summary_tail(
        self,
        summary: BusinessPayloadSummary,
        include_guids: bool = True,
        include_u32: bool = True,
        include_float_groups: bool = True,
    ) -> List[str]:
        parts: List[str] = []
        if include_guids and summary.guids:
            parts.append("编号=[" + ", ".join(self._short_id(value) for value in summary.guids) + "]")
        if summary.strings:
            parts.append("文本=[" + ", ".join(self._quote_text(value, limit=40) for value in summary.strings) + "]")
        if include_u32 and summary.u32_values:
            parts.append("数值=[" + ", ".join(str(value) for value in summary.u32_values) + "]")
        if include_float_groups and summary.float_groups:
            parts.append("浮点=[" + ", ".join(self._format_float_tuple(group) for group in summary.float_groups[:3]) + "]")
        return parts

    @staticmethod
    def _join_business_parts(parts: List[str], payload: bytes) -> str:
        if parts:
            return " ".join(parts)
        return f"原始长度={len(payload)}字节"

    @staticmethod
    def _first_guid(summary: BusinessPayloadSummary) -> Optional[str]:
        return summary.guids[0] if summary.guids else None

    @staticmethod
    def _last_u32(summary: BusinessPayloadSummary) -> Optional[int]:
        return summary.u32_values[-1] if summary.u32_values else None

    @staticmethod
    def _first_float_group(summary: BusinessPayloadSummary, minimum: int) -> Optional[Tuple[float, ...]]:
        for group in summary.float_groups:
            if len(group) >= minimum:
                return group
        return None

    def _format_float_tuple(self, values: Tuple[float, ...]) -> str:
        return "(" + ",".join(self._format_float(value) for value in values) + ")"

    @staticmethod
    def _format_float(value: float) -> str:
        if math.isnan(value):
            return "nan"
        if math.isinf(value):
            return "+inf" if value > 0 else "-inf"
        if abs(value) > 1000000.0 or (value != 0.0 and abs(value) < 0.000001):
            return f"{value:.3e}"
        text = f"{value:.3f}".rstrip("0").rstrip(".")
        return text if text else "0"

    @staticmethod
    def _unique_limited(values: List[str], limit: int) -> List[str]:
        out: List[str] = []
        for value in values:
            if value in out:
                continue
            out.append(value)
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def _telemetry_prefix(direction: str, kind: str, envelope: RpcEnvelope) -> str:
        kind_text = "请求" if kind == "request" else "响应"
        parts = [RF4ChatBridge._format_direction(direction), f"{kind_text}#{envelope.call_id}"]
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            parts.append(f"协议{envelope.main_cmd}/{envelope.sub_cmd}")
        return " ".join(parts)

    @staticmethod
    def _format_direction(direction: str) -> str:
        return "客户端->服务器" if direction == "C->S" else "服务器->客户端"

    def _format_room_push_summary(self, broadcast: RoomBroadcast) -> Optional[str]:
        if not broadcast.fish_key or not broadcast.weight_raw:
            if self._room_protocol_details_enabled():
                return f"房间状态更新 | {self._format_room_telemetry(broadcast)}"
            return None

        fish_name = self._format_fish_name(broadcast.fish_key)
        weight = self._format_chat_weight(broadcast.weight_raw)
        grade = self._format_grade_label(broadcast.line_type)
        if broadcast.line_type in {21, 22}:
            record_class = self._record_class_label(broadcast)
            label = f"频道记录[{record_class}]" if record_class else "频道记录"
            text = f"{label}：有人钓到 {fish_name} {weight}"
        elif grade:
            text = f"频道鱼获：有人钓到 [{grade}] {fish_name} {weight}"
        else:
            text = f"频道鱼获：有人钓到 {fish_name} {weight}"

        extras = []
        if broadcast.location_id:
            extras.append(f"地点={broadcast.location_id}")
        if broadcast.users_count is not None:
            extras.append(f"房间人数={broadcast.users_count}")
        if self._room_protocol_details_enabled():
            extras.append(f"消息ID={broadcast.event_id}")
            extras.append(f"类型={broadcast.line_type}")
        if extras:
            return f"{text}（{'，'.join(extras)}）"
        return text

    def _format_room_telemetry(self, broadcast: RoomBroadcast) -> str:
        parts = [
            f"事件={broadcast.event_id}",
            f"类型={broadcast.line_type}",
        ]
        if broadcast.fish_key:
            parts.append(f"鱼={self._format_fish_name(broadcast.fish_key)}")
            parts.append(f"鱼名key={broadcast.fish_key}")
        if broadcast.weight_raw:
            parts.append(f"重量={self._format_chat_weight(broadcast.weight_raw)}")
        if broadcast.location_id:
            parts.append(f"地点={broadcast.location_id}")
        if broadcast.users_count is not None:
            parts.append(f"人数={broadcast.users_count}")
        details = self._format_room_detail_items(broadcast.details)
        if details:
            parts.append(f"明细={details}")
        return " ".join(parts)

    @staticmethod
    def _format_room_detail_items(details: Tuple[RoomDetailItem, ...]) -> str:
        if not details:
            return ""
        formatted = []
        for item in details[:8]:
            kind = "文本" if item.kind == "string" else "数值" if item.kind == "u32" else item.kind
            formatted.append(f"{item.slot}:{kind}={item.value}")
        if len(details) > 8:
            formatted.append("...")
        return "[" + ", ".join(formatted) + "]"

    @staticmethod
    def _short_id(value: Optional[str]) -> str:
        if not value:
            return "unknown"
        if len(value) <= 12:
            return value
        return value[:8] + "..."

    def _detect_anticheat(self, session: FlowSession, envelope: RpcEnvelope, from_client: bool = True) -> None:
        """记录反作弊相关消息的完整内容，供识别其结构(是系统上报还是违规)。"""
        if envelope.marker != -1:
            return
        if envelope.main_cmd != session.profile.session_main_cmd:
            return
        if envelope.sub_cmd not in (8, 9):
            return
        label = self.SESSION_COMMAND_LABELS.get(envelope.sub_cmd, "反作弊")
        direction = "C->S" if from_client else "S->C"
        ascii_str = self._format_ascii_strings(envelope.payload, limit=20)
        self._log(
            f"反作弊消息 {direction} {label} "
            f"ascii={ascii_str} "
            f"hex={envelope.payload.hex()} "
            f"len={len(envelope.payload)}"
        )

    def _handle_client_frame(
        self,
        session: FlowSession,
        plain_body: bytes,
    ) -> tuple[Optional[bytes], List[bytes]]:
        envelope = parse_envelope(plain_body)
        if not envelope:
            return plain_body, []
        self._detect_anticheat(session, envelope, from_client=True)

        # 按抛竿顺序分配竿号：游戏里 1/2/3 号竿对应抛竿先后。
        # 抛竿(14/2)和准备抛竿(14/1)时把该钓组ID分配递增竿号，后续来鱼/咬钩沿用。
        if envelope.main_cmd == session.profile.fishing_main_cmd and envelope.sub_cmd in (
            session.profile.cast_sub_cmd,
            session.profile.cast_prepare_sub_cmd,
        ):
            cast_gear = parse_fishing_gear_and_setup(envelope, session.profile, envelope.sub_cmd)
            if cast_gear and cast_gear.fishing_gear_id:
                self._assign_gear_slot(session, cast_gear.fishing_gear_id)
                if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                    self._log(
                        f"cast 钓组={self._short_id(cast_gear.fishing_gear_id)} "
                        f"竿号={session.gear_slots.get(cast_gear.fishing_gear_id)} "
                        f"sub={envelope.sub_cmd}"
                    )

        # 进入搏鱼阶段(14/11)：客户端确认鱼已挂牢咬钩，触发"确认咬钩"事件。
        fight_stage = parse_fishing_gear_and_setup(envelope, session.profile, session.profile.fight_stage_sub_cmd)
        if fight_stage and fight_stage.fish_setup_id:
            meta = session.fish_setup_cache.get(fight_stage.fish_setup_id)
            if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                self._log(
                    f"fight_stage 钓组={self._short_id(fight_stage.fishing_gear_id)} "
                    f"鱼编号={self._short_id(fight_stage.fish_setup_id)} "
                    f"hex={self._hex_preview(envelope.payload, limit=160)}"
                )
            synthetic = self._build_self_synthetic_event(
                session=session,
                fish_key=meta.fish_key if meta else "",
                weight_raw=meta.weight_hint_raw if meta else 0,
                phase=self.SELF_EVENT_PHASE_BITTEN,
                fishing_gear_id=fight_stage.fishing_gear_id or (meta.fishing_gear_id if meta else None),
                fish_setup_id=fight_stage.fish_setup_id,
            )
            self._emit_self_event(session, synthetic)
            return plain_body, []

        keep_request = parse_keep_fish_request(envelope, session.profile)
        if keep_request:
            session.keep_requests[keep_request.call_id] = keep_request
            return plain_body, []

        release_request = parse_release_fish_request(envelope, session.profile)
        if release_request and release_request.fish_setup_id:
            if release_request.fish_setup_id in session.announced_fish_setup_ids:
                session.announced_fish_setup_ids.discard(release_request.fish_setup_id)
                meta = session.fish_setup_cache.get(release_request.fish_setup_id)
                synthetic = self._build_self_synthetic_event(
                    session=session,
                    fish_key=meta.fish_key if meta else "",
                    weight_raw=meta.weight_hint_raw if meta else 0,
                    phase=self.SELF_EVENT_PHASE_RELEASED,
                    fishing_gear_id=release_request.fishing_gear_id,
                    fish_setup_id=release_request.fish_setup_id,
                )
                self._emit_self_event(session, synthetic)
            return plain_body, []

        # 脱钩/脱离由客户端完成判定后上报，不能只依赖服务器方向（14/12）。
        contact_left = parse_contact_left(envelope, session.profile)
        if contact_left and contact_left.fish_setup_id:
            if contact_left.fish_setup_id in session.announced_fish_setup_ids:
                session.announced_fish_setup_ids.discard(contact_left.fish_setup_id)
                meta = session.fish_setup_cache.get(contact_left.fish_setup_id)
                synthetic = self._build_self_synthetic_event(
                    session=session,
                    fish_key=meta.fish_key if meta else "",
                    weight_raw=meta.weight_hint_raw if meta else 0,
                    phase=self.SELF_EVENT_PHASE_ESCAPED,
                    fishing_gear_id=contact_left.fishing_gear_id,
                    fish_setup_id=contact_left.fish_setup_id,
                )
                self._emit_self_event(session, synthetic)
            return plain_body, []

        public_chat = parse_public_chat_request(envelope, session.profile)
        if public_chat and public_chat.message:
            text = f"\u4f60: {self._clean_text(public_chat.message)}"
            self._log_event(text)
            self._broadcast_generic_event("chat", text)
            return plain_body, []

        ack_request = parse_room_ack_request(envelope, session.profile)
        if ack_request and ack_request.event_id is not None:
            synthetic = session.synthetic_events.pop(ack_request.event_id, None)
            if synthetic:
                session.room_events.pop(ack_request.event_id, None)
            else:
                session.room_ack_calls[envelope.call_id] = ack_request.event_id

            if synthetic:
                response_body = build_room_ack_response_body(
                    profile=session.profile,
                    call_id=envelope.call_id,
                    event_id=synthetic.event_id,
                    sender_name=synthetic.sender_name,
                    avatar_url=ctx.options.rf4_avatar_url,
                    sender_level=ctx.options.rf4_sender_level,
                    sender_region=ctx.options.rf4_sender_region,
                    sender_class=ctx.options.rf4_sender_class,
                    sender_badge=ctx.options.rf4_sender_badge,
                )
                injected = session.build_server_injection(response_body)
                return None, [injected]

        return plain_body, []

    def _handle_server_frame(self, session: FlowSession, plain_body: bytes) -> bytes:
        envelope = parse_envelope(plain_body)
        out = bytearray()
        if not envelope:
            return bytes(out)
        self._detect_anticheat(session, envelope, from_client=False)

        fish_setup = parse_fish_setup_push(envelope, session.profile)
        if fish_setup:
            session.fish_setup_cache[fish_setup.fish_setup_id] = fish_setup
            # 详细记录来鱼推送的字段，用于确认竿位编号(gear slot)的来源。
            if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                self._log(
                    f"fish_setup_push 钓组={self._short_id(fish_setup.fishing_gear_id)} "
                    f"鱼编号={self._short_id(fish_setup.fish_setup_id)} "
                    f"鱼名key={fish_setup.fish_key} setup_enum={fish_setup.setup_enum} "
                    f"hex={self._hex_preview(envelope.payload, limit=160)}"
                )
            if (
                fish_setup.weight_hint_raw
                and fish_setup.fish_setup_id not in session.announced_fish_setup_ids
            ):
                session.announced_fish_setup_ids.add(fish_setup.fish_setup_id)
                self._assign_gear_slot(session, fish_setup.fishing_gear_id)
                synthetic = self._build_self_synthetic_event(
                    session=session,
                    fish_key=fish_setup.fish_key,
                    weight_raw=fish_setup.weight_hint_raw,
                    phase=self.SELF_EVENT_PHASE_INCOMING,
                    fishing_gear_id=fish_setup.fishing_gear_id,
                )
                out.extend(self._emit_self_event(session, synthetic))
            return bytes(out)

        contact_left = parse_contact_left(envelope, session.profile)
        if contact_left and contact_left.fish_setup_id:
            if contact_left.fish_setup_id in session.announced_fish_setup_ids:
                session.announced_fish_setup_ids.discard(contact_left.fish_setup_id)
                meta = session.fish_setup_cache.get(contact_left.fish_setup_id)
                synthetic = self._build_self_synthetic_event(
                    session=session,
                    fish_key=meta.fish_key if meta else "",
                    weight_raw=meta.weight_hint_raw if meta else 0,
                    phase=self.SELF_EVENT_PHASE_ESCAPED,
                    fishing_gear_id=meta.fishing_gear_id if meta else None,
                    fish_setup_id=contact_left.fish_setup_id,
                )
                out.extend(self._emit_self_event(session, synthetic))
            return bytes(out)

        broadcast = parse_room_broadcast(envelope, session.profile)
        if broadcast:
            self._remember_room_context(session, broadcast)
            session.room_events[broadcast.event_id] = broadcast
            return bytes(out)

        request_event_id = session.room_ack_calls.pop(envelope.call_id, None)
        ack_response = parse_room_ack_response(envelope, session.profile)
        if ack_response:
            event_id = ack_response.event_id if ack_response.event_id is not None else request_event_id
            broadcast = session.room_events.pop(event_id, None) if event_id is not None else None
            line = self._format_room_chat_line(
                sender_name=ack_response.sender_name,
                broadcast=broadcast,
            )
            if line:
                self._log_event(line)
                self._broadcast_generic_event("fish_catch", line)
            return bytes(out)

        keep_request = session.keep_requests.pop(envelope.call_id, None)
        if keep_request and envelope.marker == -2:
            synthetic = self._build_synthetic_broadcast(session, keep_request, plain_body)
            catch = extract_catch_summary_from_response(plain_body)
            if keep_request.fish_setup_id:
                session.announced_fish_setup_ids.discard(keep_request.fish_setup_id)
            if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                self._log_keep_response_detail(session, keep_request, plain_body, catch, synthetic)
            if synthetic is None:
                # 缓存与响应都提取不到完整鱼名/重量时，仍发出入护事件，
                # 保证浮窗一定显示"入护"，信息不全也优于完全丢失。
                synthetic = self._build_self_synthetic_event(
                    session=session,
                    fish_key=catch.fish_key or "",
                    weight_raw=catch.weight_raw or 0,
                    phase=self.SELF_EVENT_PHASE_KEPT,
                    fishing_gear_id=keep_request.fishing_gear_id,
                    fish_setup_id=keep_request.fish_setup_id,
                )
            if synthetic:
                out.extend(self._emit_self_event(session, synthetic))

        return bytes(out)

    def _log_keep_response_detail(
        self,
        session: FlowSession,
        keep_request: KeepFishRequest,
        plain_body: bytes,
        catch: CatchSummary,
        synthetic: Optional[SyntheticChatEvent],
    ) -> None:
        """打印入护响应的完整内容，用于排查鱼名/重量提取不全的问题。"""
        details = [
            f"入护响应 call={keep_request.call_id}",
            f"fish_setup_id={self._short_id(keep_request.fish_setup_id)}",
            f"提取鱼名key={catch.fish_key or 'None'} 重量raw={catch.weight_raw or 'None'}",
        ]
        meta = None
        if keep_request.fish_setup_id:
            meta = session.fish_setup_cache.get(keep_request.fish_setup_id)
        if meta:
            details.append(
                f"缓存元数据 鱼名key={meta.fish_key} 重量raw={meta.weight_hint_raw or 'None'}"
            )
        details.append(f"合成结果={'有' if synthetic else '无'}")
        details.append(f"ascii={self._format_ascii_strings(plain_body, limit=12)}")
        details.append(f"hex={self._hex_preview(plain_body)}")
        self._log(" ".join(details))

    def _remember_room_context(self, session: FlowSession, broadcast: RoomBroadcast) -> None:
        if broadcast.location_id is not None:
            session.latest_location_id = broadcast.location_id
        if broadcast.users_count is not None:
            session.latest_users_count = broadcast.users_count

    def _assign_gear_slot(self, session: FlowSession, fishing_gear_id: Optional[str]) -> None:
        if not fishing_gear_id or fishing_gear_id in session.gear_slots:
            return
        session.gear_slots[fishing_gear_id] = session.next_gear_slot
        session.next_gear_slot += 1

    def _gear_slot_text(self, session: FlowSession, fishing_gear_id: Optional[str]) -> str:
        if not fishing_gear_id:
            return ""
        slot = session.gear_slots.get(fishing_gear_id)
        if slot is None:
            return ""
        return f"{slot}号杆"

    def _build_synthetic_broadcast(
        self,
        session: FlowSession,
        keep_request: KeepFishRequest,
        plain_body: bytes,
    ) -> Optional[SyntheticChatEvent]:
        meta = None
        if keep_request.fish_setup_id:
            meta = session.fish_setup_cache.get(keep_request.fish_setup_id)

        # 优先用来鱼时缓存的鱼信息（服务器 14/14 下发的 fish_key + 重量提示），
        # 入护响应的提取依赖位置猜测，可能失败或取错字段。
        fish_key = meta.fish_key if (meta and meta.fish_key) else None
        weight_raw = meta.weight_hint_raw if (meta and meta.weight_hint_raw) else None

        if not fish_key or not weight_raw:
            catch = extract_catch_summary_from_response(plain_body)
            if not fish_key:
                fish_key = catch.fish_key
            if not weight_raw:
                weight_raw = catch.weight_raw

        if not fish_key or not weight_raw:
            return None

        return self._build_self_synthetic_event(
            session=session,
            fish_key=fish_key,
            weight_raw=weight_raw,
            phase=self.SELF_EVENT_PHASE_KEPT,
            fishing_gear_id=keep_request.fishing_gear_id,
            fish_setup_id=keep_request.fish_setup_id,
        )

    def _build_self_synthetic_event(
        self,
        session: FlowSession,
        fish_key: str,
        weight_raw: int,
        phase: str,
        fishing_gear_id: Optional[str] = None,
        fish_setup_id: Optional[str] = None,
    ) -> SyntheticChatEvent:
        location_id = session.latest_location_id
        if location_id is None:
            location_id = ctx.options.rf4_default_location_id

        users_count = session.latest_users_count
        if users_count is None:
            users_count = ctx.options.rf4_default_users_count

        # 若钓组ID缺失，尝试从 fish_setup_cache 按 fish_setup_id 反查，保证杆号能显示。
        if not fishing_gear_id and fish_setup_id:
            meta = session.fish_setup_cache.get(fish_setup_id)
            if meta:
                fishing_gear_id = meta.fishing_gear_id

        return SyntheticChatEvent(
            event_id=session.alloc_event_id(),
            fish_key=fish_key,
            weight_raw=weight_raw,
            location_id=location_id,
            users_count=users_count,
            phase=phase,
            sender_name=self._self_sender_name(phase),
            line_type=session.profile.room_message_line_type_catch,
            fishing_gear_id=fishing_gear_id or "",
            gear_slot_text=self._gear_slot_text(session, fishing_gear_id),
        )

    def _inject_self_synthetic_event(self, session: FlowSession, synthetic: SyntheticChatEvent) -> bytes:
        session.synthetic_events[synthetic.event_id] = synthetic
        session.room_events[synthetic.event_id] = RoomBroadcast(
            line_type=synthetic.line_type,
            event_id=synthetic.event_id,
            fish_key=synthetic.fish_key,
            weight_raw=synthetic.weight_raw,
            location_id=synthetic.location_id,
            users_count=synthetic.users_count,
        )
        injected_body = build_room_message_push_body(
            profile=session.profile,
            call_id=session.alloc_call_id(),
            event_id=synthetic.event_id,
            fish_key=synthetic.fish_key,
            weight_raw=synthetic.weight_raw,
            location_id=synthetic.location_id,
            users_count=synthetic.users_count,
            line_type=synthetic.line_type,
        )
        return session.build_server_injection(injected_body)

    def _emit_self_event(self, session: FlowSession, synthetic: SyntheticChatEvent) -> bytes:
        # 日志始终全量输出；只有浮窗广播受勾选开关控制。
        self._log_self_event(self._format_self_event_log_line(synthetic))
        self._broadcast_self_event(synthetic)
        if not self._self_phase_enabled(synthetic.phase):
            return b""
        if not self._self_chat_injection_enabled():
            return b""
        if synthetic.phase in {self.SELF_EVENT_PHASE_ESCAPED, self.SELF_EVENT_PHASE_RELEASED}:
            return b""
        return self._inject_self_synthetic_event(session, synthetic)

    @staticmethod
    def _self_phase_enabled(phase: str) -> bool:
        phase_switch = {
            "incoming": "rf4_show_incoming",
            "bitten": "rf4_show_bitten",
            "kept": "rf4_show_kept",
            "escaped": "rf4_show_escaped",
            "released": "rf4_show_released",
        }.get(phase)
        if not phase_switch:
            return True
        return bool(getattr(ctx.options, phase_switch, True))

    def _broadcast_self_event(self, synthetic: SyntheticChatEvent) -> None:
        port = int(ctx.options.rf4_event_bridge_port or 0)
        if port <= 0:
            return
        phase_switch = {
            self.SELF_EVENT_PHASE_INCOMING: "rf4_show_incoming",
            self.SELF_EVENT_PHASE_BITTEN: "rf4_show_bitten",
            self.SELF_EVENT_PHASE_KEPT: "rf4_show_kept",
            self.SELF_EVENT_PHASE_ESCAPED: "rf4_show_escaped",
            self.SELF_EVENT_PHASE_RELEASED: "rf4_show_released",
        }.get(synthetic.phase)
        if phase_switch and not bool(getattr(ctx.options, phase_switch, True)):
            return
        fish_name = self._format_fish_name(synthetic.fish_key or "")
        event_name = {
            self.SELF_EVENT_PHASE_INCOMING: "fish_incoming",
            self.SELF_EVENT_PHASE_BITTEN: "fish_bitten",
            self.SELF_EVENT_PHASE_KEPT: "fish_kept",
            self.SELF_EVENT_PHASE_ESCAPED: "fish_escaped",
            self.SELF_EVENT_PHASE_RELEASED: "fish_released",
        }.get(synthetic.phase, "fish_kept")
        payload = json.dumps(
            {
                "event": event_name,
                "fish_key": synthetic.fish_key,
                "fish_name": fish_name,
                "weight_g": synthetic.weight_raw,
                "gear_slot": synthetic.gear_slot_text,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(payload.encode("utf-8"), (ctx.options.rf4_event_bridge_host, port))
            finally:
                sock.close()
        except OSError:
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"failed to broadcast self event on {ctx.options.rf4_event_bridge_host}:{port}"
                )

    def _broadcast_generic_event(self, event_name: str, text: str) -> None:
        """广播其他事件(频道鱼获/公共聊天等)到浮窗，受显示设置勾选控制。"""
        port = int(ctx.options.rf4_event_bridge_port or 0)
        if port <= 0:
            return
        switch = {
            "fish_catch": "rf4_show_catch_broadcast",
            "chat": "rf4_show_chat_broadcast",
        }.get(event_name)
        if switch and not bool(getattr(ctx.options, switch, True)):
            return
        payload = json.dumps(
            {
                "event": event_name,
                "text": text,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(payload.encode("utf-8"), (ctx.options.rf4_event_bridge_host, port))
            finally:
                sock.close()
        except OSError:
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"failed to broadcast {event_name} on {ctx.options.rf4_event_bridge_host}:{port}"
                )

    @staticmethod
    def _format_weight(weight_raw: Optional[int]) -> str:
        if not weight_raw:
            return "unknown"
        return f"{weight_raw}g/{weight_raw / 1000:.3f}kg"

    def _format_room_chat_line(self, sender_name: Optional[str], broadcast: Optional[RoomBroadcast]) -> Optional[str]:
        if not broadcast:
            return None
        if broadcast.weight_raw and broadcast.fish_key:
            if broadcast.line_type in {21, 22}:
                return self._format_record_chat_line(sender_name or "unknown", broadcast)
            return self._format_catch_chat_line(
                sender_name or "unknown",
                broadcast.fish_key,
                broadcast.weight_raw,
                line_type=broadcast.line_type,
            )
        if broadcast.fish_key:
            text = self._clean_text(broadcast.fish_key)
            if sender_name:
                return f"{sender_name}: {text}"
            return text
        return None

    def _format_catch_chat_line(
        self,
        sender_name: str,
        fish_key: str,
        weight_raw: int,
        line_type: Optional[int] = None,
    ) -> str:
        fish_name = self._format_fish_name(fish_key)
        grade = self._format_grade_label(line_type)
        if grade:
            return f"{sender_name} 钓到了 [{grade}] {self._format_chat_weight(weight_raw)} {fish_name}"
        return f"{sender_name} 钓到了 {self._format_chat_weight(weight_raw)} {fish_name}"

    def _format_self_event_log_line(self, event: SyntheticChatEvent) -> str:
        fish_name = self._format_fish_name(event.fish_key)
        weight = self._format_chat_weight(event.weight_raw)
        prefix = f"[{event.gear_slot_text}]" if event.gear_slot_text else ""
        if event.phase == self.SELF_EVENT_PHASE_INCOMING:
            return f"【我自己】：{prefix} 有{fish_name} {weight} 过来了"
        if event.phase == self.SELF_EVENT_PHASE_BITTEN:
            return f"【我自己】：{prefix} {fish_name} 咬钩了"
        if event.phase == self.SELF_EVENT_PHASE_ESCAPED:
            return f"【我自己】：{prefix} {fish_name} {weight} 挣脱跑了（脱钩）"
        if event.phase == self.SELF_EVENT_PHASE_RELEASED:
            return f"【我自己】：{prefix} 放生了 {fish_name}"
        return f"【我自己】：{prefix} 有{fish_name} {weight} 入护了"

    def _format_record_chat_line(self, sender_name: str, broadcast: RoomBroadcast) -> str:
        fish_name = self._format_fish_name(broadcast.fish_key or "")
        record_class = self._record_class_label(broadcast)
        if record_class:
            return f"{sender_name} 记录[{record_class}] 钓到了 {self._format_chat_weight(broadcast.weight_raw or 0)} {fish_name}"
        return f"{sender_name} 记录 钓到了 {self._format_chat_weight(broadcast.weight_raw or 0)} {fish_name}"

    def _format_fish_name(self, fish_key: str) -> str:
        return self._fish_labels_zh.get(fish_key, fish_key)

    def _self_sender_name(self, phase: str) -> str:
        if phase == self.SELF_EVENT_PHASE_INCOMING:
            return "【我自己·过来了】"
        if phase == self.SELF_EVENT_PHASE_ESCAPED:
            return "【我自己·脱钩】"
        if phase == self.SELF_EVENT_PHASE_RELEASED:
            return "【我自己·放生】"
        return "【我自己·入护了】"

    def _format_grade_label(self, line_type: Optional[int]) -> Optional[str]:
        if line_type is None:
            return None
        return self.GRADE_LABELS_BY_LINE_TYPE.get(line_type)

    def _record_class_label(self, broadcast: RoomBroadcast) -> Optional[str]:
        for item in broadcast.details:
            if item.slot == 6 and item.kind == "string" and item.value:
                return self.RECORD_CLASS_LABELS.get(str(item.value), str(item.value))
        return None

    @staticmethod
    def _format_chat_weight(weight_raw: int) -> str:
        if weight_raw < 1000:
            return f"{weight_raw} 克"
        return f"{weight_raw / 1000:.3f} 公斤"

    @staticmethod
    def _clean_text(text: str) -> str:
        return " ".join(text.replace("\r", " ").replace("\n", " ").split())

    def _log_http_message(self, label: str, headline: str, headers, body_text: str) -> None:
        header_lines = self._format_headers(headers)
        parts = [label, headline]
        if header_lines:
            parts.extend(header_lines)
        else:
            parts.append("<no headers>")
        parts.append("")
        parts.append(body_text if body_text else "<empty body>")
        self._log("\n".join(parts))

    def _describe_plain_body(self, plain_body: bytes) -> str:
        envelope = parse_envelope(plain_body)
        if envelope is None:
            strings = self._format_ascii_strings(plain_body)
            return (
                f"plain=raw ascii={strings} "
                f"hex={self._hex_preview(plain_body)}"
            )

        label = "request" if envelope.marker == -1 else "response"
        details = [f"plain={label}", f"call={envelope.call_id}"]
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            details.append(f"cmd={envelope.main_cmd}/{envelope.sub_cmd}")
        payload = envelope.payload or plain_body
        details.append(f"ascii={self._format_ascii_strings(payload)}")
        details.append(f"hex={self._hex_preview(payload)}")
        return " ".join(details)

    @staticmethod
    def _format_headers(headers) -> List[str]:
        if headers is None:
            return []
        items = None
        if hasattr(headers, "items"):
            try:
                items = headers.items(multi=True)
            except TypeError:
                items = headers.items()
        if items is None:
            return [str(headers)]
        return [f"{key}: {value}" for key, value in items]

    @staticmethod
    def _extract_message_text(message) -> str:
        if message is None:
            return ""
        getter = getattr(message, "get_text", None)
        if callable(getter):
            try:
                return getter(strict=False)
            except TypeError:
                try:
                    return getter()
                except ValueError:
                    pass
            except ValueError:
                pass
        raw_content = getattr(message, "raw_content", None)
        if raw_content in (None, b""):
            return ""
        if isinstance(raw_content, bytes):
            return raw_content.decode("utf-8", errors="replace")
        return str(raw_content)

    @staticmethod
    def _format_ascii_strings(data: bytes, limit: int = 8) -> str:
        values = []
        for value in ascii_strings(data, min_len=4):
            if value in values:
                continue
            values.append(value)
            if len(values) >= limit:
                break
        if not values:
            return "<none>"
        compact = [RF4ChatBridge._quote_text(value, limit=80) for value in values]
        joined = ", ".join(compact)
        if len(values) >= limit and len(ascii_strings(data, min_len=4)) > limit:
            joined += ", ..."
        return joined

    @staticmethod
    def _hex_preview(data: bytes, limit: int = 96) -> str:
        preview = data[:limit].hex()
        if len(data) > limit:
            preview += "..."
        return preview or "<empty>"

    @staticmethod
    def _quote_text(text: str, limit: int = 120) -> str:
        compact = text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")
        if len(compact) > limit:
            compact = compact[:limit - 3] + "..."
        return f'"{compact}"'

if __name__ != "__main__":
    addons = [RF4ChatBridge()]
else:
    addons = []

if __name__ == "__main__":
    raise SystemExit(main())
