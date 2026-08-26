import json
import math
import os
import re
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union


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
from .fish_labels import (
    CACHE_DIR,
    load_fish_grade_config,
    load_fish_labels,
    load_unlocalized_fish_keys,
)
from .launcher import parse_https_upstream_map, rewrite_login_logon_info
from .protocol import (
    BuildingRpcRequest,
    BusinessPayloadSummary,
    CatchSummary,
    FishSaleResult,
    FishSetupMeta,
    FishingEndRequest,
    ItemCatalogEntry,
    ItemObjectSummary,
    ItemStateSummary,
    KeepFishRequest,
    ObservedCatchRecord,
    PhoenixArgument,
    RC4Stream,
    RepairRequestSummary,
    RF4ProtocolProfile,
    RigComponentSummary,
    RigDefinitionSummary,
    RoomBroadcast,
    RoomDetailItem,
    RpcEnvelope,
    SlotItemSummary,
    WorkshopDiagnosisSummary,
    ascii_strings,
    build_ack_frame,
    build_frame,
    build_room_ack_response_body,
    build_room_message_push_body,
    extract_catch_summary_from_response,
    get_profile,
    guid_le,
    is_complete_but_invalid_auth_packet,
    parse_admin_status,
    parse_cafe_delivery_result,
    parse_contact_left,
    parse_envelope,
    parse_fish_sale_results,
    parse_fish_setup_push,
    parse_fishing_end_request,
    parse_fishing_gear_and_setup,
    parse_item_scope_summary,
    parse_item_state_summary,
    parse_keep_fish_request,
    parse_observed_catch_records,
    parse_public_chat_request,
    parse_release_fish_request,
    parse_room_ack_request,
    parse_room_ack_response,
    parse_room_broadcast,
    parse_shop_result_text,
    parse_slot_items_response_payload,
    parse_tagged_i64,
    parse_typed_arguments,
    parse_workshop_diagnosis,
    read_arg_header,
    read_guid_array,
    read_marked_string,
    read_typed_list_header,
    take_complete_frames,
    try_parse_auth_packet,
    try_parse_first_frame,
    try_parse_uuid_packet,
    u16,
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

THIS_DIR = Path(__file__).resolve().parent

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
    grade_enum: Optional[int] = None


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
    fish_setup_by_gear: Dict[str, str] = field(default_factory=lambda: BoundedDict(512))
    fight_fish_by_gear: Dict[str, str] = field(default_factory=lambda: BoundedDict(512))
    fight_distance_by_gear: Dict[str, float] = field(default_factory=lambda: BoundedDict(512))
    fishing_end_requests: Dict[int, FishingEndRequest] = field(default_factory=lambda: BoundedDict(128))
    keep_requests: Dict[int, KeepFishRequest] = field(default_factory=lambda: BoundedDict(128))
    rpc_request_commands: Dict[int, Tuple[int, int, float]] = field(default_factory=lambda: BoundedDict(512))
    building_request_calls: Dict[int, BuildingRpcRequest] = field(default_factory=lambda: BoundedDict(256))
    slot_request_calls: Dict[int, int] = field(default_factory=lambda: BoundedDict(128))
    item_guid_to_id: Dict[str, Tuple[int, int]] = field(default_factory=lambda: BoundedDict(2048))
    observed_catches: Dict[str, ObservedCatchRecord] = field(default_factory=lambda: BoundedDict(2048))
    room_events: Dict[int, RoomBroadcast] = field(default_factory=lambda: BoundedDict(512))
    room_ack_calls: Dict[int, int] = field(default_factory=lambda: BoundedDict(128))
    synthetic_events: Dict[int, SyntheticChatEvent] = field(default_factory=lambda: BoundedDict(64))
    synthetic_wire_ids: set[int] = field(default_factory=lambda: BoundedSet(64))
    announced_fish_setup_ids: set[str] = field(default_factory=lambda: BoundedSet(256))
    latest_location_id: Optional[str] = None
    latest_users_count: Optional[int] = None
    slot_items: Dict[int, str] = field(default_factory=dict)
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
    # 启动时解密本地部件目录（多文件×多变体，较慢）；测试套件置 False 跳过。
    ALLOW_STARTUP_CACHE_DECRYPT = True
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
    ITEM_COMMAND_LABELS = {
        1: "物品位置概览",
        4: "物品位置分页",
        5: "物品详情读取",
        22: "装备/物品更新",
    }
    SLOT_COMMAND_LABELS = {
        1: "请求当前装备槽位",
        2: "切换装备槽位",
    }
    GEAR_GROUP_LABELS = {
        "rod_spinning": "纺车路亚竿",
        "rod_casting": "枪柄路亚竿",
        "rod_feeder_legacy": "老式飞德竿",
        "rod_pilker": "Pilker 海钓竿",
        "rod_boat": "船钓竿",
        "rod_telescopic": "手竿",
        "rod_bolognese": "博洛尼亚竿",
        "rod_match": "赛竿",
        "rod_roubaisienne": "Roubaisienne 长竿",
        "rod_fly_one_hand": "单手飞蝇竿",
        "rod_fly_two_hand": "双手飞蝇竿",
        "rod_picker": "Picker 竿",
        "rod_feeder": "飞德竿",
        "rod_carp": "鲤鱼竿",
        "rod_jerking": "抽停竿",
        "rod_spod": "打窝竿",
        "rod_marker": "标记竿",
        "rod_other": "其他鱼竿",
        "reel_spinning": "纺车轮",
        "reel_baitcasting_low": "低轮廓水滴轮",
        "reel_baitcasting_round": "圆形鼓轮",
        "reel_conventional": "传统海钓轮",
        "reel_fly": "飞蝇轮",
        "reel_other": "其他卷线器",
        "line_mono": "尼龙线",
        "line_fluorocarbon": "碳氟线",
        "line_braid": "编织线",
        "line_other": "其他主线",
        "hook": "鱼钩",
    }
    CONFIG_TYPE_INFO = {
        12046: (157, "rod"),
        12035: (149, "reel"),
        12024: (140, "line"),
        12020: (131, "hook"),
    }
    ROD_SUBTYPES = {
        0: "rod_feeder_legacy",
        1: "rod_spinning",
        2: "rod_casting",
        3: "rod_telescopic",
        4: "rod_bolognese",
        5: "rod_match",
        6: "rod_roubaisienne",
        7: "rod_fly_one_hand",
        8: "rod_fly_two_hand",
        9: "rod_picker",
        10: "rod_feeder",
        11: "rod_carp",
        12: "rod_jerking",
        13: "rod_spod",
        14: "rod_marker",
        15: "rod_pilker",
        16: "rod_boat",
    }
    REEL_SUBTYPES = {
        1: "reel_spinning",
        2: "reel_baitcasting_low",
        3: "reel_baitcasting_round",
        4: "reel_conventional",
        5: "reel_fly",
    }
    LINE_SUBTYPES = {
        1: "line_mono",
        2: "line_fluorocarbon",
        3: "line_braid",
    }
    _AUTHORITATIVE_GEAR_OBJECT_TYPES = frozenset({157, 149, 140, 131})
    GEAR_TYPE_INFO = {object_type_id: base_group for config_type_id, (object_type_id, base_group) in CONFIG_TYPE_INFO.items()}
    CATEGORY_LABELS = {
        "rod": "鱼竿",
        "reel": "卷线器",
        "line": "鱼线",
        "hook": "鱼钩",
        "lure": "拟饵",
        "bait": "饵料",
        "float": "浮漂",
        "sinker": "铅坠",
        "cloth": "服装",
        "food": "食物",
        "map": "地图",
        "aux": "辅助物品",
        "other": "其他",
    }
    BUILDING_COMMAND_LABELS = {
        (3, 13): "场地厨房进食",
        (3, 25): "场景管理处处罚状态查询",
        (3, 26): "登录处罚欢迎提示查询",
        (4, 1): "物品位置概览",
        (4, 4): "物品位置分页",
        (4, 5): "物品详情读取",
        (4, 6): "仓储/物品位置转移",
        (4, 7): "物品位置操作",
        (4, 8): "使用物品/执行物品动作",
        (20, 2): "鱼市出售",
        (20, 4): "咖啡馆订单交付",
        (21, 2): "工坊诊断",
        (21, 3): "工坊金币维修",
        (21, 4): "工坊普通维修",
        (22, 2): "商店银币购买",
        (22, 3): "商店金币购买",
        (22, 4): "商店退货",
        (25, 3): "船只/载具位置操作",
        (25, 4): "加油站确认加油",
        (25, 6): "加油站询价",
    }
    BUILDING_DOMAIN_LABELS = {
        20: "鱼市/咖啡馆",
        21: "工坊",
        22: "商店",
        25: "船只/载具服务",
    }
    GEAR_CATALOG_CATEGORIES = {
        "rod",
        "reel",
        "line",
        "hook",
        "lure",
        "bait",
        "float",
        "sinker",
        "aux",
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
        self._item_catalog_index: Dict[int, Tuple[ItemCatalogEntry, ...]] = {}
        self._catalog_key_lookup: Dict[str, ItemCatalogEntry] = {}
        try:
            self._load_item_catalog_index()
        except Exception:
            pass
        self._gear_config_by_id: Dict[int, dict] = {}
        self._gear_config_hashes: List[str] = []
        try:
            self._restore_gear_config_hashes()
        except Exception:
            pass
        try:
            self._load_gear_config_from_cache()
        except Exception:
            pass
        self._show_cfg_path = getattr(getattr(ctx, "options", None), "rf4_show_config_path", "") or ""
        self._show_cfg_mtime = 0.0
        self._show_cfg_cache: Dict[Tuple[str, bool], bool] = {}
        self._show_cfg_min_interval = 1.0  # 秒，避免每次广播读盘
        self._fish_grade_labels, self._fish_grade_by_line_type = load_fish_grade_config()
        self._unlocalized_fish_keys = load_unlocalized_fish_keys()

    def _gear_hash_store_path(self) -> Path:
        """配置版本 hash 的持久化位置（.cache 目录，打包态在 exe 旁）。"""
        return CACHE_DIR / "gear_config_hashes.json"

    def _restore_gear_config_hashes(self) -> None:
        """恢复上次运行捕获的配置版本 hash，使启动时即可解密本地部件目录。

        hash 仅在登录流量中出现且此前只存内存，重启即丢；持久化后只要成功
        捕获过一次，之后每次启动都能解密出完整部件目录（游戏更新配置版本
        后会被新捕获的 hash 覆盖）。
        """
        try:
            payload = json.loads(self._gear_hash_store_path().read_text("utf-8"))
        except (OSError, ValueError):
            return
        hashes = payload.get("hashes") if isinstance(payload, dict) else None
        if isinstance(hashes, list):
            self._gear_config_hashes = [str(h) for h in hashes if str(h)]
    def _persist_gear_config_hashes(self) -> None:
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            self._gear_hash_store_path().write_text(
                json.dumps(
                    {"hashes": list(dict.fromkeys(self._gear_config_hashes))},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except OSError:
            pass

    def _load_gear_config_from_cache(self) -> None:
        # 测试套件通过类开关跳过真实解密（慢：多文件 × 多变体 RC4/SHA1）。
        if not self.__class__.ALLOW_STARTUP_CACHE_DECRYPT:
            return
        try:
            from .game_catalog import (
                extract_gear_config_records_from_cache,
                local_config_cache_candidates,
                preferred_local_config_cache_path,
            )
        except Exception:
            return
        try:
            cache_paths = local_config_cache_candidates()
        except Exception:
            cache_paths = []
        known_system_ids = {
            key
            for key in self._fish_labels_zh
            if key and not key.startswith("card_")
        }
        best: list = []
        best_hash = ""
        # 优先用运行时捕获的 configs_version hash 解密缓存(否则缓存是加密的)；
        # 找不到 hash 时再退回到未解密数据(仅对未加密的旧缓存有效)。
        hashes = list(self._gear_config_hashes or ())
        if not hashes:
            hashes = [""]
        for cache_hash in hashes:
            for path in cache_paths:
                try:
                    records = extract_gear_config_records_from_cache(
                        path=path,
                        known_system_ids=None if cache_hash else known_system_ids,
                        cache_hash=cache_hash or None,
                    )
                except Exception:
                    records = []
                if len(records) > len(best):
                    best = records
                    best_hash = cache_hash
        by_id: Dict[int, dict] = {}
        for record in best:
            attributes = dict(record.attributes)
            by_id[int(record.config_id)] = {
                "config_id": int(record.config_id),
                "system_id": str(record.system_id),
                "object_type_id": int(record.object_type_id),
                "group_key": str(record.group_key),
                "attributes": attributes,
            }
        self._gear_config_by_id = by_id
        if self._gear_config_by_id:
            self._log(
                f"已从游戏本地缓存读取真实装备部件目录：{len(self._gear_config_by_id)} 件"
                + (f" (hash={best_hash[:8]}...)" if best_hash else "")
            )
        elif hashes and hashes != [""]:
            # 有 hash 却解不出：缓存文件缺失/版本不匹配，需要用户感知而非静默。
            self._log(
                "未能从游戏本地配置缓存解密出部件目录"
                f"(尝试 {len(hashes)} 个版本 hash)；将在下次登录捕获新 hash 后重试"
            )

    def _load_item_catalog_index(self) -> None:
        candidates = [
            THIS_DIR.parent / "catalog" / "catalog.json",
            THIS_DIR / "catalog" / "catalog.json",
            Path(sys.argv[0]).resolve().parent / "catalog" / "catalog.json",
        ]
        for path in candidates:
            if not path.exists():
                continue
            try:
                payload = json.loads(path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            categories = payload.get("cats") if isinstance(payload.get("cats"), dict) else {}
            items = payload.get("items") if isinstance(payload.get("items"), list) else []
            index: Dict[int, List[ItemCatalogEntry]] = {}
            key_lookup: Dict[str, ItemCatalogEntry] = {}
            for raw_item in items:
                if not isinstance(raw_item, dict):
                    continue
                catalog_id = str(raw_item.get("id") or "").strip()
                if not catalog_id:
                    continue
                category = str(raw_item.get("cat") or raw_item.get("sub") or "").strip()
                name = str(raw_item.get("name") or raw_item.get("en") or catalog_id).strip()
                raw_stats = raw_item.get("stats") if isinstance(raw_item.get("stats"), dict) else {}
                entry = ItemCatalogEntry(
                    catalog_id=catalog_id,
                    category=category,
                    category_label=str(categories.get(category) or category or "物品"),
                    name=name or catalog_id,
                    stats=dict(raw_stats),
                )
                key_lookup.setdefault(catalog_id, entry)
                for token in re.findall(r"\d+", catalog_id):
                    item_id = int(token)
                    if item_id <= 0:
                        continue
                    index.setdefault(item_id, []).append(entry)
            self._item_catalog_index = {item_id: tuple(entries) for item_id, entries in index.items()}
            self._catalog_key_lookup = key_lookup
            return

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
            "rf4_log_building_protocol_details",
            bool,
            True,
            "Print field-level building/shop request/response details (store, fish market, workshop, boat).",
        )
        loader.add_option(
            "rf4_log_equipment_details",
            bool,
            True,
            "Print field-level equipment/item state payloads (gear rod/reel/line/hook details).",
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
        loader.add_option("rf4_show_fight_status", bool, True, "Show fight status line broadcast (搏鱼状态行).")
        loader.add_option("rf4_show_fight_details", bool, True, "Show fight process detail telemetry (位置上报/拉线/脱钩).")
        loader.add_option("rf4_show_player", bool, True, "Show player telemetry logs (坐标/状态).")
        loader.add_option("rf4_show_feed", bool, True, "Show feed telemetry logs (打窝/投喂).")
        loader.add_option("rf4_show_chat", bool, True, "Show chat telemetry logs (公共聊天/频道鱼获).")
        loader.add_option("rf4_show_room", bool, True, "Show room telemetry logs (房间消息).")
        loader.add_option("rf4_show_session", bool, True, "Show session telemetry logs (会话信息).")
        loader.add_option("rf4_show_unknown", bool, True, "Show unknown telemetry logs (未知协议).")
        loader.add_option("rf4_show_item", bool, True, "Show item/equipment telemetry logs (装备/物品).")
        loader.add_option("rf4_show_building", bool, True, "Show building/shop telemetry logs (商店/鱼市/工坊/船).")
        loader.add_option("rf4_show_catch_broadcast", bool, True, "Show other players' catch broadcasts in overlay (频道鱼获).")
        loader.add_option("rf4_show_chat_broadcast", bool, True, "Show public chat in overlay (公共聊天).")
        loader.add_option(
            "rf4_show_config_path",
            str,
            "",
            "Path to rf4_show_config.json so show toggles can be hot-reloaded at runtime. Empty = use --set flags only.",
        )

    def configure(self, updated) -> None:
        self._profile = get_profile(ctx.options.rf4_profile)
        self._fish_labels_zh = dict(self.DEFAULT_FISH_LABELS_ZH)
        try:
            self._fish_labels_zh.update(load_fish_labels(self._profile.name))
        except Exception:
            pass
        self._fish_grade_labels, self._fish_grade_by_line_type = load_fish_grade_config()
        self._unlocalized_fish_keys = load_unlocalized_fish_keys()
        # 显示开关热重载缓存：记录配置文件路径与上次读取时间，运行时变更可被周期感知。
        self._show_cfg_path = getattr(ctx.options, "rf4_show_config_path", "") or ""
        self._show_cfg_mtime = 0.0
        self._show_cfg_cache: Dict[Tuple[str, bool], bool] = {}
        self._show_cfg_min_interval = 1.0  # 秒，避免每次广播读盘

    def _show_enabled(self, option_name: str) -> bool:
        """显示开关运行时解析：配置文件中用短键(如 incoming/catch_broadcast)。

        优先读 rf4_show_config.json 的短键值，否则回退到 --set/option 默认值。
        """
        fallback = bool(getattr(ctx.options, option_name, True))
        if not self._show_cfg_path:
            return fallback
        key = self._option_name_to_key(option_name)
        try:
            mtime = os.stat(self._show_cfg_path).st_mtime
            if mtime != self._show_cfg_mtime:
                with open(self._show_cfg_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    self._show_cfg_cache = {
                        str(k): bool(v) for k, v in data.items() if isinstance(v, bool)
                    }
                self._show_cfg_mtime = mtime
            if key in self._show_cfg_cache:
                return self._show_cfg_cache[key]
        except (OSError, ValueError, TypeError):
            pass
        return fallback

    def _option_name_to_key(self, option_name: str) -> str:
        # 托盘 rf4_show_config.json 使用短键，这里把 option 名反转成短键
        return {
            "rf4_show_incoming": "incoming",
            "rf4_show_bitten": "bitten",
            "rf4_show_kept": "kept",
            "rf4_show_escaped": "escaped",
            "rf4_show_released": "released",
            "rf4_show_catch_broadcast": "catch_broadcast",
            "rf4_show_chat_broadcast": "chat_broadcast",
            "rf4_show_fish": "telemetry_fish",
            "rf4_show_fight_status": "fight_status",
            "rf4_show_fight_details": "fight_details",
            "rf4_show_player": "telemetry_player",
            "rf4_show_feed": "telemetry_feed",
            "rf4_show_chat": "telemetry_chat",
            "rf4_show_room": "telemetry_room",
            "rf4_show_session": "telemetry_session",
            "rf4_show_unknown": "telemetry_unknown",
            "rf4_show_item": "telemetry_item",
            "rf4_show_building": "telemetry_building",
        }.get(option_name, option_name)

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
        self._broadcast_telemetry(category, text)

    def _broadcast_telemetry(self, category: str, text: str) -> None:
        port = int(getattr(ctx.options, "rf4_event_bridge_port", 0) or 0)
        if port <= 0:
            return
        switch = self._telemetry_show_option(category)
        if switch and not self._show_enabled(switch):
            return
        payload = json.dumps(
            {
                "event": "telemetry",
                "category": category,
                "text": text,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                host = getattr(ctx.options, "rf4_event_bridge_host", None) or "127.0.0.1"
                sock.sendto(payload.encode("utf-8"), (host, port))
            finally:
                sock.close()
        except OSError:
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"failed to broadcast telemetry {category} on {getattr(ctx.options, 'rf4_event_bridge_host', None) or '127.0.0.1'}:{port}"
                )

    @staticmethod
    def _telemetry_show_option(category: str) -> str:
        return {
            "fish": "rf4_show_fish",
            "fight_status": "rf4_show_fight_status",
            "fight_details": "rf4_show_fight_details",
            "player": "rf4_show_player",
            "feed": "rf4_show_feed",
            "chat": "rf4_show_chat",
            "room": "rf4_show_room",
            "session": "rf4_show_session",
            "unknown": "rf4_show_unknown",
            "item": "rf4_show_item",
            "building": "rf4_show_building",
        }.get(category, "rf4_show_unknown")

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
    def _building_protocol_details_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_log_building_protocol_details", True))

    @staticmethod
    def _equipment_details_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_log_equipment_details", True))

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

    @staticmethod
    def _uuid_prefix_is_possible(data: bytes) -> bool:
        """按字节前缀判断是否仍可能是 36 字节 UUID（连字符固定位 8/13/18/23 + hex）。

        服务端握手缓冲里积累的如果是普通业务数据，前缀很快就与 UUID 形状不符，
        此时无需再等待 1MB 超时，直接透传即可。
        """
        hex_bytes = b"0123456789abcdefABCDEF"
        hyphen_positions = {8, 13, 18, 23}
        for index, value in enumerate(data[:36]):
            if index in hyphen_positions:
                if value != 0x2D:
                    return False
            elif value not in hex_bytes:
                return False
        return True

    def _enter_passthrough(
        self,
        flow: tcp.TCPFlow,
        session: FlowSession,
        reason: str,
        *,
        from_client: bool,
        pending: bytes | None = None,
    ) -> bytes:
        """进入字节级透传，并把已缓冲的同向数据整体回放、对向探测半包立即释放。

        首包判定期间，对向可能已收到探测半包；若透传后才交给后续转发，这些字节会
        滞留在旧握手缓冲中丢失（商店/建筑等辅助通道常见）。这里在切换透传的瞬间
        用 inject.tcp 把对向半包回放给对方，同向缓冲则整体返回给调用方转发。
        """
        if session.passthrough:
            return pending if pending is not None else b""
        session.passthrough = True
        # 释放对向探测半包（client 触发则把 server_buffer 回放给 client，反之亦然）。
        opposite_buffer = session.server_buffer if from_client else session.client_buffer
        if opposite_buffer:
            pending_opposite = bytes(opposite_buffer)
            try:
                ctx.master.commands.call("inject.tcp", flow, from_client, pending_opposite)
            except Exception as exc:
                if ctx.options.rf4_verbose_logging:
                    self._log(
                        f"passthrough opposite replay failed flow={flow.id}: {exc} "
                        f"(will be prefix-replayed by same-side fallback)"
                    )
            else:
                opposite_buffer.clear()
        if ctx.options.rf4_verbose_logging:
            self._log(f"entering passthrough flow={flow.id} reason={reason}")
        buffered = bytes(session.client_buffer if from_client else session.server_buffer)
        session.client_buffer.clear() if from_client else session.server_buffer.clear()
        if pending is not None:
            buffered = buffered + bytes(pending)
        return buffered

    def _process_client_bytes(self, flow: tcp.TCPFlow, session: FlowSession, chunk: bytes) -> bytes:
        if session.passthrough:
            # 透传后同向可能仍有未回放的残留字节（对向释放失败时），前缀回放兜底。
            if session.client_buffer:
                chunk = bytes(session.client_buffer) + bytes(chunk)
                session.client_buffer.clear()
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
                    return self._enter_passthrough(
                        flow, session, "client non-RF4 first bytes", from_client=True
                    )
            else:
                # 数据不足 2 字节，先缓冲等待更多数据。
                return b""
            parsed = try_parse_auth_packet(bytes(session.client_buffer))
            if parsed is None:
                if is_complete_but_invalid_auth_packet(bytes(session.client_buffer)):
                    # 已凑齐完整认证包长度却解析失败，确定不是 RF4 realtime 认证连接，
                    # 立即透传并回放缓冲，无需等待 1MB 超时。
                    self._log(
                        f"client invalid auth packet flow={flow.id} "
                        f"len={len(session.client_buffer)}; entering passthrough"
                    )
                    return self._enter_passthrough(
                        flow, session, "client invalid auth packet", from_client=True
                    )
                if len(session.client_buffer) > self.MAX_HANDSHAKE_BUFFER:
                    # 数据不符合 RF4 认证包格式，进入透传模式（原样转发），
                    # 避免把非认证连接（如商店的额外 realtime 连接）的数据吞掉。
                    self._log(
                        f"client handshake timeout flow={flow.id} "
                        f"len={len(session.client_buffer)}; entering passthrough"
                    )
                    return self._enter_passthrough(
                        flow, session, "client handshake overflow", from_client=True
                    )
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
                    return self._enter_passthrough(
                        flow, session, "client hermes buffer overflow", from_client=True,
                        pending=bytes(out),
                    )
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
                return self._enter_passthrough(
                    flow, session, "client non-hermes frame after auth", from_client=True,
                    pending=bytes(out),
                )
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
            # 透传后同向残留字节前缀回放兜底（对向释放失败时）。
            if session.server_buffer:
                chunk = bytes(session.server_buffer) + bytes(chunk)
                session.server_buffer.clear()
            return chunk
        session.server_buffer.extend(chunk)
        out = bytearray()

        if not session.uuid_seen:
            if not self._uuid_prefix_is_possible(bytes(session.server_buffer)):
                # 服务端数据前缀已不可能成为 36 字节 UUID，说明这不是 realtime 握手，
                # 无需等待 1MB 超时，立即透传并回放已缓冲字节。
                self._log(
                    f"server non-UUID data flow={flow.id} "
                    f"first_bytes={session.server_buffer[:16].hex()} "
                    f"len={len(session.server_buffer)}; entering passthrough"
                )
                return self._enter_passthrough(
                    flow, session, "server non-UUID first bytes", from_client=False
                )
            parsed = try_parse_uuid_packet(bytes(session.server_buffer))
            if parsed is None:
                if len(session.server_buffer) > self.MAX_HANDSHAKE_BUFFER:
                    self._log(
                        f"server handshake buffer overflow flow={flow.id} "
                        f"len={len(session.server_buffer)}; entering passthrough"
                    )
                    return self._enter_passthrough(
                        flow, session, "server handshake overflow", from_client=False
                    )
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
            if from_client:
                try:
                    self._track_rpc_request_command(session, plain_body)
                    self._track_building_rpc_request(session, plain_body)
                except Exception:
                    pass
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
            building = self._describe_building_request(session, envelope)
            if building:
                return building
            fishing_end_request = parse_fishing_end_request(envelope, session.profile)
            if fishing_end_request:
                meta = self._fish_setup_meta_for_request(session, fishing_end_request)
                fish_key = meta.fish_key if meta else None
                fish_name = self._format_fish_name(fish_key) if fish_key else "unknown"
                weight = self._format_chat_weight(meta.weight_hint_raw) if meta and meta.weight_hint_raw else "unknown"
                return (
                    "fish",
                    f"请求结算鱼获 | 鱼={fish_name} 鱼名key={fish_key or 'unknown'} "
                    f"预估重量={weight} 鱼编号={self._short_id(fishing_end_request.fish_setup_id or (meta.fish_setup_id if meta else None))} "
                    f"钓组={self._short_id(fishing_end_request.fishing_gear_id)}",
                )

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
            building = self._describe_building_response(session, envelope)
            if building:
                return building
            fishing_end_request = session.fishing_end_requests.get(envelope.call_id)
            if fishing_end_request and envelope.marker == -2:
                catch = extract_catch_summary_from_response(plain_body)
                fish_key = catch.fish_key
                weight_raw = catch.weight_raw
                meta = self._fish_setup_meta_for_request(session, fishing_end_request)
                if meta:
                    fish_key = fish_key or meta.fish_key
                    weight_raw = weight_raw or meta.weight_hint_raw
                fish_name = self._format_fish_name(fish_key) if fish_key else "unknown"
                weight = self._format_chat_weight(weight_raw) if weight_raw else "unknown"
                return (
                    "fish",
                    f"结算结果 | 鱼={fish_name} 鱼名key={fish_key or 'unknown'} "
                    f"重量={weight} 规格={catch.size_enum} 鱼编号={self._short_id(fishing_end_request.fish_setup_id)}",
                )

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

            slot_request_sub_cmd = session.slot_request_calls.get(envelope.call_id)
            if slot_request_sub_cmd is not None and envelope.marker == -2:
                try:
                    self._remember_server_slot_items(session, plain_body, slot_request_sub_cmd)
                except Exception:
                    pass
                if self._equipment_details_enabled():
                    slots = parse_slot_items_response_payload(envelope.payload)
                    if slots:
                        label = self.SLOT_COMMAND_LABELS.get(slot_request_sub_cmd, "装备槽位响应")
                        return "item", self._format_business_line(label, self._format_slot_items(slots, session))

            catalog_keys = self._extract_gear_catalog_keys(envelope.payload)
            if envelope.marker == -2 and catalog_keys:
                request_command = session.rpc_request_commands.get(envelope.call_id)
                protocol = (
                    f"{request_command[0]}/{request_command[1]}"
                    if request_command is not None
                    else "unknown"
                )
                formatted = [self._format_system_item_name(value) for value in catalog_keys[:12]]
                if len(catalog_keys) > 12:
                    formatted.append(f"…+{len(catalog_keys) - 12}")
                category = (
                    "building"
                    if request_command is not None and request_command[0] in {20, 21, 22, 25}
                    else "item"
                )
                label = "建筑/商店资源目录" if category == "building" else "资源名称目录"
                return (
                    category,
                    f"{label}响应#{envelope.call_id} | 来源协议={protocol} "
                    f"名称数={len(catalog_keys)} 名称=[{'; '.join(formatted)}]",
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
            return "fight_details", self._format_business_line(label, details)
        elif sub_cmd == profile.fight_load_sub_cmd:
            slim = self._format_fight_load_payload(session, envelope.payload)
            if slim:
                return "fight_status", slim
            return None
        elif sub_cmd == profile.fight_pull_sub_cmd:
            details = self._format_fight_pull_payload(session, envelope.payload)
            return "fight_details", self._format_business_line(label, details)
        elif sub_cmd == profile.fight_stage_sub_cmd:
            slim = self._format_fight_stage_initial_line(session, envelope)
            if slim:
                return "fight_status", slim
            return None
        elif sub_cmd == profile.contact_left_sub_cmd:
            details = self._format_contact_left_payload(envelope.payload)
            return "fight_details", self._format_business_line(label, details)
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

        if envelope.main_cmd == 4:
            label = self.ITEM_COMMAND_LABELS.get(envelope.sub_cmd)
            if envelope.sub_cmd == 22:
                if not self._equipment_details_enabled():
                    return None
                try:
                    self._remember_gear_item_guids(session, envelope.payload)
                except Exception:
                    pass
                item_details = self._format_item_state_payload(envelope.payload)
                if not item_details:
                    return None
                return "item", self._format_business_line(label or "装备/物品更新", item_details)
            if not self._low_level_telemetry_enabled():
                return None
            if label:
                return "item", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if envelope.main_cmd == profile.fishing_main_cmd:
            label = self.FISHING_COMMAND_LABELS.get(envelope.sub_cmd)
            if label:
                return "fish", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
        return None

    def _track_rpc_request_command(self, session: FlowSession, plain_body: bytes) -> None:
        envelope = parse_envelope(plain_body)
        if (
            envelope is None
            or envelope.marker != -1
            or envelope.main_cmd is None
            or envelope.sub_cmd is None
        ):
            return
        session.rpc_request_commands[envelope.call_id] = (
            envelope.main_cmd,
            envelope.sub_cmd,
            time.monotonic(),
        )
        if len(session.rpc_request_commands) > 512:
            oldest_call = min(
                session.rpc_request_commands,
                key=lambda call_id: session.rpc_request_commands[call_id][2],
            )
            session.rpc_request_commands.pop(oldest_call, None)

    def _track_building_rpc_request(self, session: FlowSession, plain_body: bytes) -> None:
        if not self._building_protocol_details_enabled():
            return
        envelope = parse_envelope(plain_body)
        if (
            envelope is None
            or envelope.marker != -1
            or envelope.main_cmd is None
            or envelope.sub_cmd is None
            or (
                (envelope.main_cmd, envelope.sub_cmd) not in self.BUILDING_COMMAND_LABELS
                and envelope.main_cmd not in self.BUILDING_DOMAIN_LABELS
            )
        ):
            return
        try:
            arguments = parse_typed_arguments(envelope.payload)
        except (ValueError, IndexError, struct.error):
            arguments = ()
        session.building_request_calls[envelope.call_id] = BuildingRpcRequest(
            call_id=envelope.call_id,
            main_cmd=envelope.main_cmd,
            sub_cmd=envelope.sub_cmd,
            arguments=arguments,
            payload=bytes(envelope.payload),
            created_at=time.monotonic(),
        )
        if len(session.building_request_calls) > 256:
            oldest = min(
                session.building_request_calls.values(),
                key=lambda value: value.created_at,
            )
            session.building_request_calls.pop(oldest.call_id, None)

    @staticmethod
    def _building_argument(trace: BuildingRpcRequest, index: int) -> Optional[PhoenixArgument]:
        if index < 0 or index >= len(trace.arguments):
            return None
        return trace.arguments[index]

    @staticmethod
    def _building_argument_value(trace: BuildingRpcRequest, index: int, default=None):
        argument = RF4ChatBridge._building_argument(trace, index)
        return argument.value if argument is not None else default

    @staticmethod
    def _numeric_building_argument(trace: BuildingRpcRequest, index: int) -> Optional[int]:
        argument = RF4ChatBridge._building_argument(trace, index)
        if argument is None or argument.kind not in {"i32", "u32", "i64"}:
            return None
        return int(argument.value)

    @staticmethod
    def _guid_array_building_argument(trace: BuildingRpcRequest, index: int) -> Tuple[str, ...]:
        argument = RF4ChatBridge._building_argument(trace, index)
        if argument is None or argument.kind != "guid_array" or not isinstance(argument.value, tuple):
            return ()
        return tuple(str(value) for value in argument.value)

    @staticmethod
    def _format_money_raw(value: int) -> str:
        return f"{int(value) / 100.0:.2f} (raw={int(value)})"

    def _format_system_item_name(self, system_id: object) -> str:
        key = str(system_id or "").strip()
        if not key:
            return "unknown"
        game_name = str(self._fish_labels_zh.get(key) or "").strip()
        if game_name and game_name != key:
            return f"{self._quote_text(self._clean_text(game_name), limit=60)}({key})"
        # 物品实例 system_id 常带变体后缀(如 tele_10175_5_9 / spin_6115_g)，
        # 基础 model 名(tele_10175_5 / spin_6115)在目录表里。逐段去掉尾部后缀再查。
        trimmed = key
        while "_" in trimmed:
            trimmed, _, _ = trimmed.rpartition("_")
            base_name = str(self._fish_labels_zh.get(trimmed) or "").strip()
            if base_name and base_name != trimmed:
                return f"{self._quote_text(self._clean_text(base_name), limit=60)}({trimmed} 变体)"
            prefix = trimmed + "_"
            family = sorted(
                name for name, label in self._fish_labels_zh.items()
                if name.startswith(prefix) and str(label or "").strip() and label != name
            )
            if family:
                family_name = str(self._fish_labels_zh.get(family[0]) or "").strip()
                return (
                    f"{self._quote_text(self._clean_text(family_name), limit=60)}"
                    f"({trimmed} 变体)"
                )
        return key

    def _format_guid_sequence(self, values: Sequence[str], limit: int = 8) -> str:
        items = [self._short_id(str(value)) for value in values[:limit]]
        if len(values) > limit:
            items.append(f"…+{len(values) - limit}")
        return "[" + ", ".join(items) + "]"

    def _format_observed_catch(self, session: FlowSession, guid: str) -> str:
        record = session.observed_catches.get(guid)
        if record is None:
            return self._short_id(guid)
        fish_name = self._format_fish_name(record.fish_key)
        return (
            f"{fish_name}/{self._format_chat_weight(record.weight_raw)}"
            f"/{self._short_id(guid)}"
        )

    def _format_catch_guid_sequence(
        self,
        session: FlowSession,
        values: Sequence[str],
        limit: int = 8,
    ) -> str:
        items = [self._format_observed_catch(session, str(value)) for value in values[:limit]]
        if len(values) > limit:
            items.append(f"…+{len(values) - limit}")
        return "[" + "; ".join(items) + "]"

    def _format_repair_request_summary(self, request: RepairRequestSummary) -> str:
        selections = [
            f"{value.component_type}"
            + (f"/{value.component_key}" if value.component_key else "")
            for value in request.selections[:12]
        ]
        if len(request.selections) > 12:
            selections.append(f"…+{len(request.selections) - 12}")
        return (
            f"物品={self._short_id(request.item_guid)} "
            f"部件=[{', '.join(selections)}] "
            f"选项={str(request.option_enabled).lower()} "
            f"报价={self._format_money_raw(request.quoted_cost_raw)}"
        )

    def _format_phoenix_arguments(self, arguments: Sequence[PhoenixArgument]) -> str:
        values: List[str] = []
        for index, argument in enumerate(arguments[:12], start=1):
            if argument.kind == "guid":
                value = self._short_id(str(argument.value))
            elif argument.kind == "guid_array" and isinstance(argument.value, tuple):
                value = self._format_guid_sequence(argument.value)
            elif argument.kind == "repair_request" and isinstance(argument.value, RepairRequestSummary):
                value = self._format_repair_request_summary(argument.value)
            elif argument.kind == "string":
                value = self._quote_text(str(argument.value or ""), limit=60)
            elif argument.kind == "bool":
                value = str(bool(argument.value)).lower()
            else:
                value = str(argument.value)
            values.append(f"{index}:{argument.kind}={value}")
        if len(arguments) > 12:
            values.append(f"…+{len(arguments) - 12}")
        return "参数=[" + "; ".join(values) + "]" if values else "无参数"

    def _building_command_label(self, command: Tuple[int, int]) -> str:
        verified = self.BUILDING_COMMAND_LABELS.get(command)
        if verified:
            return verified
        domain = self.BUILDING_DOMAIN_LABELS.get(command[0], "建筑/商店")
        return f"{domain}未识别操作 {command[0]}/{command[1]}"

    def _describe_building_request(
        self,
        session: FlowSession,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if not self._building_protocol_details_enabled():
            return None
        trace = session.building_request_calls.get(envelope.call_id)
        if trace is None:
            return None
        command = (trace.main_cmd, trace.sub_cmd)
        label = self._building_command_label(command)
        parts: List[str] = []

        if command in {(22, 2), (22, 3)}:
            store_id = self._building_argument_value(trace, 0, "")
            system_id = self._building_argument_value(trace, 1, "")
            cost_raw = self._numeric_building_argument(trace, 2)
            parts.extend(
                (
                    f"商店={self._quote_text(str(store_id or ''), limit=60)}",
                    f"物品={self._format_system_item_name(system_id)}",
                    f"支付={'金币' if command == (22, 3) else '银币'}",
                )
            )
            if cost_raw is not None:
                parts.append(f"报价={self._format_money_raw(cost_raw)}")
        elif command == (22, 4):
            parts.append(f"商店={self._quote_text(str(self._building_argument_value(trace, 0, '')), limit=60)}")
            parts.append(f"物品={self._short_id(str(self._building_argument_value(trace, 1, '')))}")
        elif command == (20, 2):
            fish_ids = self._guid_array_building_argument(trace, 1)
            parts.append(f"鱼市={self._quote_text(str(self._building_argument_value(trace, 0, '')), limit=60)}")
            parts.append(f"鱼={self._format_catch_guid_sequence(session, fish_ids)}")
            parts.append(f"数量={len(fish_ids)}")
        elif command == (20, 4):
            fish_ids = self._guid_array_building_argument(trace, 2)
            parts.append(f"咖啡馆/市场={self._quote_text(str(self._building_argument_value(trace, 0, '')), limit=60)}")
            parts.append(f"订单={self._short_id(str(self._building_argument_value(trace, 1, '')))}")
            parts.append(f"鱼={self._format_catch_guid_sequence(session, fish_ids)}")
            parts.append(f"数量={len(fish_ids)}")
        elif command == (21, 2):
            parts.append(f"工坊={self._quote_text(str(self._building_argument_value(trace, 0, '')), limit=60)}")
            parts.append(f"物品={self._short_id(str(self._building_argument_value(trace, 1, '')))}")
        elif command in {(21, 3), (21, 4)}:
            parts.append(f"工坊={self._quote_text(str(self._building_argument_value(trace, 0, '')), limit=60)}")
            request = self._building_argument_value(trace, 1)
            if isinstance(request, RepairRequestSummary):
                parts.append(self._format_repair_request_summary(request))
        elif command in {(25, 4), (25, 6)}:
            parts.append(f"船={self._short_id(str(self._building_argument_value(trace, 0, '')))}")
            parts.append(f"加油站={self._quote_text(str(self._building_argument_value(trace, 1, '')), limit=60)}")
        elif command in {(3, 25), (3, 26)}:
            parts.append("无参数")
        elif command == (25, 3):
            parts.append(f"位置枚举={self._numeric_building_argument(trace, 0)}")
            parts.append(f"船只/载具={self._short_id(str(self._building_argument_value(trace, 1, '')))}")
        elif command == (3, 13):
            parts.append(f"厨房={self._quote_text(str(self._building_argument_value(trace, 0, '')), limit=60)}")
        elif command == (4, 1):
            parts.append(f"位置={self._numeric_building_argument(trace, 0)}")
        elif command == (4, 4):
            parts.extend(
                (
                    f"位置={self._numeric_building_argument(trace, 0)}",
                    f"偏移={self._numeric_building_argument(trace, 1)}",
                    f"数量={self._numeric_building_argument(trace, 2)}",
                )
            )
        elif command == (4, 5):
            item_ids = self._guid_array_building_argument(trace, 1)
            parts.append(f"位置={self._numeric_building_argument(trace, 0)}")
            parts.append(f"物品={self._format_guid_sequence(item_ids)}")
            parts.append(f"数量={len(item_ids)}")
        elif command == (4, 6):
            item_ids = self._guid_array_building_argument(trace, 0)
            parts.append(f"物品={self._format_guid_sequence(item_ids)}")
            parts.append(f"从={self._numeric_building_argument(trace, 1)}")
            parts.append(f"到={self._numeric_building_argument(trace, 2)}")
        elif command in {(4, 7), (4, 8)}:
            parts.append(self._format_phoenix_arguments(trace.arguments))

        if not parts or not trace.arguments and command not in {(3, 25), (3, 26)}:
            details = (
                self._format_phoenix_arguments(trace.arguments)
                if trace.arguments
                else self._format_generic_business_payload(trace.payload)
            )
            if details not in parts:
                parts.append(details)
        category = "item" if command[0] == 4 else "building"
        return category, f"{label}请求#{trace.call_id} | {' '.join(parts)}"

    def _remember_observed_catches(
        self,
        session: FlowSession,
        records: Sequence[ObservedCatchRecord],
    ) -> None:
        for record in records:
            session.observed_catches[record.record_guid] = record
        if len(session.observed_catches) > 2048:
            for guid in tuple(session.observed_catches)[: len(session.observed_catches) - 2048]:
                session.observed_catches.pop(guid, None)

    def _format_workshop_diagnosis(self, summary: WorkshopDiagnosisSummary) -> str:
        parts: List[str] = []
        for value in summary.parts[:12]:
            condition = (
                f"{max(0.0, min(1.0, value.condition)) * 100.0:.1f}%"
                if math.isfinite(value.condition) and -0.001 <= value.condition <= 1.2
                else self._format_float(value.condition)
            )
            parts.append(
                f"{self._short_id(value.part_guid)} "
                f"状态={condition} 银币={self._format_money_raw(value.silver_raw)} "
                f"金币={self._format_money_raw(value.gold_raw)} "
                f"耗时/数量={value.duration_or_count} 状态枚举={value.status} "
                f"子项={value.subpart_count}"
            )
        if len(summary.parts) > 12:
            parts.append(f"…+{len(summary.parts) - 12}")
        return (
            f"物品={self._short_id(summary.item_guid)} 部件=["
            + "; ".join(parts)
            + "]"
        )

    def _format_building_response_fallback(self, payload: bytes) -> str:
        if not payload or payload in {b"\x00", b"\x0e"}:
            return "服务器已确认"
        details = self._format_generic_business_payload(payload)
        if payload[:1] == b"\x01" and len(payload) >= 5:
            return f"对象type={u32(payload, 1)} {details}"
        return details

    @staticmethod
    def _extract_gear_catalog_keys(payload: bytes) -> List[str]:
        prefixes = (
            "spin_",
            "tele_",
            "bolo_",
            "match_",
            "picker_",
            "feeder_",
            "carp_",
            "ffish_",
            "bcr_",
            "conv_",
            "rgm_",
            "RGM_",
            "mono_",
            "braid_",
            "fluoro_",
            "jhead_",
        )
        out: List[str] = []
        for value in ascii_strings(payload, min_len=6):
            if not value.startswith(prefixes):
                continue
            compact = value[:80]
            if compact not in out:
                out.append(compact)
        return out

    def _gear_item_group_hint_from_rig_component(self, line_type: Optional[int]) -> Optional[str]:
        if line_type == 17:
            return "rod_lure"
        if line_type == 28:
            return "rod_hand"
        if line_type == 12:
            return "line_main"
        if line_type == 27:
            return "hook"
        return None

    def _gear_group_matches(self, config_group: str, hint_group: str) -> bool:
        config_base = config_group.split("_", 1)[0] if "_" in config_group else config_group
        hint_base = hint_group.split("_", 1)[0] if "_" in hint_group else hint_group
        if config_base == hint_base:
            return True
        return config_group.startswith(hint_group) or hint_group.startswith(config_group)

    def _gear_config_by_id_lookup(self, item_id: int) -> Optional[dict]:
        config = self._gear_config_by_id.get(item_id)
        if config:
            system_id = str(config.get("system_id") or "")
            catalog_name = ""
            game_name = str(self._fish_labels_zh.get(system_id) or "").strip()
            if game_name and game_name != system_id:
                catalog_name = game_name
            else:
                entry = self._catalog_key_lookup.get(system_id)
                if entry:
                    catalog_name = entry.name
            config = dict(config)
            config["catalog_name"] = catalog_name
            return config
        entries = self._item_catalog_index.get(item_id)
        if not entries:
            return None
        for entry in entries:
            if not entry.catalog_id.startswith(("spin_", "tele_", "bolo_", "match_", "picker_", "feeder_", "carp_", "ffish_", "bcr_", "conv_", "rgm_", "RGM_", "mono_", "braid_", "fluoro_", "jhead_")):
                continue
            category = entry.category
            group_key = {
                "rod": "rod_other",
                "reel": "reel_other",
                "line": "line_other",
                "hook": "hook",
            }.get(category)
            if not group_key:
                continue
            return {
                "config_id": item_id,
                "system_id": entry.catalog_id,
                "object_type_id": 0,
                "group_key": group_key,
                "attributes": dict(entry.stats),
                "catalog_name": entry.name,
                "category": category,
            }
        return None

    def _format_item_id(
        self,
        item_id: int,
        *,
        object_type_id: Optional[int] = None,
        group_hint: Optional[str] = None,
    ) -> str:
        config = self._gear_config_by_id_lookup(item_id)
        if config:
            category = str(config.get("category") or "")
            group_key = str(config.get("group_key") or "")
            group_label = (
                self.CATEGORY_LABELS.get(category)
                or self.GEAR_GROUP_LABELS.get(group_key, "装备部件")
            )
            catalog_name = str(config.get("catalog_name") or "")
            return f"itemId={item_id}({group_label}/{catalog_name})"
        return f"itemId={item_id}"

    def _format_item_catalog_stats(
        self,
        item_id: int,
        *,
        object_type_id: Optional[int] = None,
        group_hint: Optional[str] = None,
    ) -> str:
        config = self._gear_config_by_id_lookup(item_id)
        if not config:
            return ""
        attributes = config.get("attributes")
        if not isinstance(attributes, dict):
            return ""
        details: List[str] = []
        reel_size = int(attributes.get("reel_size", 0) or 0)
        if reel_size > 0:
            details.append(f"轮尺寸={reel_size}")
        allowed_sizes = [
            int(value)
            for value in attributes.get("allowed_reel_sizes", [])
            if int(value) > 0
        ]
        if allowed_sizes:
            details.append("适配轮尺寸=" + "/".join(str(value) for value in allowed_sizes))
        if not details:
            return ""
        return "属性(" + ", ".join(details) + ")"

    def _looks_like_ratio(self, value: Optional[float]) -> bool:
        return value is not None and math.isfinite(value) and -0.001 <= value <= 1.25

    def _format_percent(self, value: float) -> str:
        return f"{max(0.0, min(1.0, value)) * 100.0:.1f}%"

    def _format_item_condition(self, durability: Optional[float], condition: Optional[float]) -> str:
        parts: List[str] = []
        if durability is not None:
            if self._looks_like_ratio(durability):
                state = max(0.0, min(1.0, durability))
                parts.append(f"状态={self._format_percent(state)}")
                parts.append(f"磨损≈{self._format_percent(1.0 - state)}")
            else:
                parts.append(f"数量/状态={self._format_float(durability)}")
        if condition is not None:
            if self._looks_like_ratio(condition):
                label = "上限/成色"
                if durability is not None and self._looks_like_ratio(durability) and abs(condition - durability) < 0.0005:
                    label = "成色"
                parts.append(f"{label}={self._format_percent(max(0.0, min(1.0, condition)))}")
            else:
                parts.append(f"上限/状态={self._format_float(condition)}")
        return " ".join(parts)

    def _format_rig_component(self, component: RigComponentSummary) -> str:
        parts: List[str] = []
        group_hint = self._gear_item_group_hint_from_rig_component(component.line_type)
        if component.line_type is not None:
            parts.append(f"类型{component.line_type}")
        if component.item_id is not None:
            parts.append(self._format_item_id(component.item_id, group_hint=group_hint))
            stats = self._format_item_catalog_stats(component.item_id, group_hint=group_hint)
            if stats:
                parts.append(stats)
        if component.component_guid:
            parts.append(f"guid={self._short_id(component.component_guid)}")
        return " ".join(parts) if parts else "unknown"

    def _format_item_object_summary(self, item: ItemObjectSummary) -> str:
        parts: List[str] = []
        if item.item_id is not None:
            parts.append(self._format_item_id(item.item_id, object_type_id=item.object_type_id))
            stats = self._format_item_catalog_stats(
                item.item_id,
                object_type_id=item.object_type_id,
            )
            if stats:
                parts.append(stats)
        else:
            parts.append("未知物品")
        parts.append(f"对象type={item.object_type_id}")
        if item.slot is not None:
            parts.append(f"槽位/类别={item.slot}")
        if item.durability is not None or item.condition is not None:
            parts.append(self._format_item_condition(item.durability, item.condition))
        if item.item_guid:
            parts.append(f"物品={self._short_id(item.item_guid)}")
        if item.parent_guid:
            parts.append(f"父钓组={self._short_id(item.parent_guid)}")
        return " ".join(parts)

    def _format_slot_items(
        self,
        slots: Tuple[SlotItemSummary, ...],
        session: Optional[FlowSession] = None,
    ) -> str:
        formatted = []
        for slot in slots[:12]:
            label = self._slot_item_label(session, slot.item_guid)
            formatted.append(f"槽位{slot.slot_type}={label}")
        if len(slots) > 12:
            formatted.append(f"…+{len(slots) - 12}")
        return "[" + "; ".join(formatted) + "]" if formatted else "无"

    def _slot_item_label(self, session: Optional[FlowSession], item_guid: str) -> str:
        short_id = self._short_id(item_guid)
        if not session:
            return short_id
        resolved = session.item_guid_to_id.get(item_guid)
        if not resolved:
            return short_id
        item_id, object_type_id = resolved
        name = self._format_item_id(item_id, object_type_id=object_type_id)
        return f"{name} {short_id}"

    def _remember_gear_item_guids(self, session: FlowSession, payload: bytes) -> None:
        summary = parse_item_state_summary(payload)
        for item in summary.item_objects:
            if not item.item_guid or item.item_id is None:
                continue
            session.item_guid_to_id[item.item_guid] = (item.item_id, item.object_type_id)
        for rig in summary.rig_definitions:
            for component in rig.components:
                if not component.component_guid or component.item_id is None:
                    continue
                session.item_guid_to_id[component.component_guid] = (component.item_id, 152)

    def _remember_config_version_hashes(self, session: FlowSession, payload: bytes) -> None:
        try:
            from .game_catalog import decode_config_version_hashes
        except Exception:
            return
        try:
            hashes = decode_config_version_hashes(payload)
        except (ValueError, IndexError) as exc:
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"game/configs 1/5 响应无法解析为 hash 列表：{exc} "
                    f"前16字节={payload[:16].hex()} 长度={len(payload)}"
                )
            return
        if not hashes:
            return
        self._gear_config_hashes = list(dict.fromkeys(hashes))
        # 捕获成功必须可见（此前被 verbose 开关吞掉，难以定位部件目录为何为空）。
        self._log(
            f"已捕获 game/configs 配置版本 hash {len(self._gear_config_hashes)} 个，"
            "已持久化供启动解密部件目录"
        )
        self._persist_gear_config_hashes()
        if not self._gear_config_by_id:
            self._load_gear_config_from_cache()

    def _format_item_state_payload(self, payload: bytes) -> str:
        summary = parse_item_state_summary(payload)
        parts: List[str] = []
        for rig in summary.rig_definitions[:3]:
            rig_parts = [f"类型={self._format_system_item_name(rig.rig_key)}"]
            if rig.line_type is not None:
                rig_parts.append(f"lineType={rig.line_type}")
            if rig.components:
                rig_parts.append(
                    "组件=["
                    + ", ".join(self._format_rig_component(component) for component in rig.components[:8])
                    + "]"
                )
            parts.append("钓组定义{" + " ".join(rig_parts) + "}")
        if summary.item_objects:
            formatted_items = [
                self._format_item_object_summary(item)
                for item in summary.item_objects[:8]
            ]
            if len(summary.item_objects) > 8:
                formatted_items.append("...")
            parts.append("装备/物品状态=[" + "; ".join(formatted_items) + "]")
        catalog_keys = self._extract_gear_catalog_keys(payload)
        if catalog_keys:
            parts.append("名称key=[" + ", ".join(catalog_keys[:12]) + (", ..." if len(catalog_keys) > 12 else "") + "]")
        return " ".join(part for part in parts if part)

    def _describe_building_response(
        self,
        session: FlowSession,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if not self._building_protocol_details_enabled() or envelope.marker != -2:
            return None
        trace = session.building_request_calls.get(envelope.call_id)
        if trace is None:
            return None
        command = (trace.main_cmd, trace.sub_cmd)
        label = self._building_command_label(command)
        payload = envelope.payload
        details = ""

        if command == (20, 2):
            results = parse_fish_sale_results(payload)
            if results:
                lines = []
                total_raw = 0
                for value in results[:12]:
                    if value.status == 0:
                        total_raw += value.paid_raw
                    lines.append(
                        f"{self._format_observed_catch(session, value.fish_guid)} "
                        f"金额={self._format_money_raw(value.paid_raw)} 状态={value.status}"
                    )
                if len(results) > 12:
                    lines.append(f"…+{len(results) - 12}")
                details = (
                    f"结果=[{'; '.join(lines)}] "
                    f"成功合计={self._format_money_raw(total_raw)}"
                )
        elif command == (20, 4):
            result = parse_cafe_delivery_result(payload)
            if result is not None:
                details = f"奖励={self._format_money_raw(result[0])} 状态={result[1]}"
        elif command == (21, 2):
            result = parse_workshop_diagnosis(payload)
            if result is not None:
                details = self._format_workshop_diagnosis(result)
        elif command in {(21, 3), (21, 4)}:
            item_details = self._format_item_state_payload(payload) if self._equipment_details_enabled() else ""
            details = item_details or self._format_building_response_fallback(payload)
        elif command in {(22, 2), (22, 3)}:
            result_text = parse_shop_result_text(payload)
            item_details = self._format_item_state_payload(payload) if self._equipment_details_enabled() else ""
            parts = []
            if result_text:
                parts.append(f"回执={self._quote_text(self._clean_text(result_text), limit=100)}")
            if item_details:
                parts.append(item_details)
            if not parts:
                details = self._format_building_response_fallback(payload)
            else:
                details = " ".join(parts)
        elif command == (25, 6):
            price_raw = parse_tagged_i64(payload)
            if price_raw is not None:
                details = f"报价={self._format_money_raw(price_raw)}"
        elif command in {(3, 25), (3, 26)}:
            result = parse_admin_status(payload)
            if result is not None:
                details = (
                    f"文本={self._quote_text(self._clean_text(result[0] or ''), limit=100)} "
                    f"数值={self._format_float(result[1])}"
                )
        elif command == (4, 1):
            result = parse_item_scope_summary(payload)
            if result is not None:
                details = (
                    f"可用/总数={result[0]} 容量/起点={result[1]} "
                    f"限制/页大小={result[2]}"
                )
        elif command == (4, 4):
            try:
                values, _ = read_guid_array(payload, 0, marker=True)
            except (ValueError, IndexError):
                values = ()
            if values or payload.startswith(b"\x06\x00\x00"):
                details = f"数量={len(values)} 物品={self._format_guid_sequence(values, limit=12)}"
        elif command == (4, 5):
            catches = parse_observed_catch_records(payload)
            if catches:
                self._remember_observed_catches(session, catches)
                values = [
                    f"{self._format_fish_name(value.fish_key)}/"
                    f"{self._format_chat_weight(value.weight_raw)}/"
                    f"规格={value.size_enum}/{self._short_id(value.record_guid)}"
                    for value in catches[:12]
                ]
                if len(catches) > 12:
                    values.append(f"…+{len(catches) - 12}")
                details = f"鱼获数量={len(catches)} 鱼获=[{'; '.join(values)}]"
            else:
                item_details = self._format_item_state_payload(payload) if self._equipment_details_enabled() else ""
                details = item_details or self._format_building_response_fallback(payload)
        elif command == (4, 8):
            item_details = self._format_item_state_payload(payload) if self._equipment_details_enabled() else ""
            details = item_details or self._format_building_response_fallback(payload)

        if not details:
            catalog_keys = self._extract_gear_catalog_keys(payload)
            if catalog_keys:
                formatted = [self._format_system_item_name(value) for value in catalog_keys[:20]]
                if len(catalog_keys) > 20:
                    formatted.append(f"…+{len(catalog_keys) - 20}")
                details = f"资源名称数={len(catalog_keys)} 名称=[{'; '.join(formatted)}]"
        if not details:
            details = self._format_building_response_fallback(payload)
        category = "item" if command[0] == 4 else "building"
        return category, f"{label}响应#{trace.call_id} | {details}"

    @staticmethod
    def _fish_setup_meta_for_request(
        session: FlowSession,
        request: Union[FishingEndRequest, KeepFishRequest],
    ) -> Optional[FishSetupMeta]:
        if request.fish_setup_id:
            meta = session.fish_setup_cache.get(request.fish_setup_id)
            if meta:
                return meta
        if request.fishing_gear_id:
            setup_id = session.fish_setup_by_gear.get(request.fishing_gear_id)
            if setup_id:
                return session.fish_setup_cache.get(setup_id)
        return None

    @staticmethod
    def _fish_meta_for_gear(session: FlowSession, fishing_gear_id: Optional[str]) -> Optional[FishSetupMeta]:
        if not fishing_gear_id:
            return None
        setup_id = session.fish_setup_by_gear.get(fishing_gear_id)
        if not setup_id:
            return None
        return session.fish_setup_cache.get(setup_id)

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
        # 搏鱼过程采样：列出全部检测到的浮点组，观察体力/力量系数是否随过程变化。
        groups = self._scan_float_groups(payload, limit=8)
        for index, group in enumerate(groups):
            label = "坐标" if index == 0 and len(group) >= 3 else f"浮点{index + 1}"
            parts.append(f"{label}={self._format_float_tuple(group)}")
        tick = self._last_u32(summary)
        if tick is not None:
            parts.append(f"序号={tick}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_fight_load_payload(self, session: FlowSession, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        gear = self._first_guid(summary)
        if not gear:
            return ""
        gear_slot = self._gear_slot_text(session, gear)
        if not gear_slot:
            # 手持装备(不在快捷键槽位)没有竿号，但搏鱼状态仍要显示：
            # 用"手持竿"前缀兜底，否则体力和出线信息会整体丢失。
            gear_slot = "手持竿"
        groups = self._scan_float_groups(payload, limit=8)
        stamina = self._fight_stamina(groups)
        distance = self._sanitize_distance(
            self._fight_distance(groups),
            session.fight_distance_by_gear.get(gear),
        )
        parts = [gear_slot]
        setup_id = session.fight_fish_by_gear.get(gear) or session.fish_setup_by_gear.get(gear)
        meta = session.fish_setup_cache.get(setup_id) if setup_id else None
        if meta:
            grade = self._format_grade_enum(meta.setup_enum)
            if grade:
                parts.append(f"[{grade}]")
            fish_name = self._format_fish_name(meta.fish_key or "")
            weight = self._format_chat_weight(meta.weight_hint_raw) if meta.weight_hint_raw else "unknown"
            if fish_name:
                parts.append(f"鱼={fish_name}")
            if weight != "unknown":
                parts.append(f"重量={weight}")
        if stamina is not None:
            parts.append(f"体力 {stamina}%")
        if distance is not None:
            parts.append(f"出线 {self._format_float(distance)}米")
        if len(parts) == 1:
            return parts[0]
        return parts[0] + " | " + " ".join(parts[1:])

    def _format_fight_pull_payload(self, session: FlowSession, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        gear = self._first_guid(summary)
        if gear:
            parts.append(f"钓组={self._short_id(gear)}")
            setup_id = session.fight_fish_by_gear.get(gear) or session.fish_setup_by_gear.get(gear)
            meta = session.fish_setup_cache.get(setup_id) if setup_id else None
            if meta:
                parts.append(f"鱼编号={self._short_id(meta.fish_setup_id)}")
                fish_name = self._format_fish_name(meta.fish_key or "")
                weight = self._format_chat_weight(meta.weight_hint_raw) if meta.weight_hint_raw else "unknown"
                parts.append(f"鱼={fish_name} 重量={weight}")
            distance = session.fight_distance_by_gear.get(gear)
            if distance is not None:
                parts.append(f"出线={self._format_float(distance)}米")
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

    def _format_fight_stage_initial_line(self, session: FlowSession, envelope: RpcEnvelope) -> Optional[str]:
        """进入搏鱼阶段(14/11)的初始浮窗行：竿号 + 鱼名/重量 + 体力 100% + 初始出线。"""
        fight_stage = parse_fishing_gear_and_setup(
            envelope, session.profile, session.profile.fight_stage_sub_cmd
        )
        if not fight_stage or not fight_stage.fishing_gear_id:
            return None
        gear_slot = self._gear_slot_text(session, fight_stage.fishing_gear_id)
        if not gear_slot:
            # 手持装备(不在快捷键槽位)没有竿号，用"手持竿"兜底显示搏鱼初始行。
            gear_slot = "手持竿"
        meta = session.fish_setup_cache.get(fight_stage.fish_setup_id or "") if fight_stage.fish_setup_id else None
        fish_name = self._format_fish_name(meta.fish_key or "") if meta else ""
        weight = self._format_chat_weight(meta.weight_hint_raw) if meta and meta.weight_hint_raw else ""
        initial_distance = None
        for group in self._scan_float_groups(envelope.payload, limit=8):
            if group and self._is_valid_distance(group[0]):
                initial_distance = group[0]
                break
        parts = [gear_slot]
        grade = self._format_grade_enum(meta.setup_enum) if meta else None
        if grade:
            parts.append(f"[{grade}]")
        if fish_name:
            parts.append(f"鱼={fish_name}")
        if weight:
            parts.append(f"重量={weight}")
        parts.append("体力 100%")
        if initial_distance is not None:
            parts.append(f"出线 {self._format_float(initial_distance)}米")
        if len(parts) == 1:
            return parts[0]
        return parts[0] + " | " + " ".join(parts[1:])

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
    def _fight_distance(groups: Tuple[Tuple[float, ...], ...]) -> Optional[float]:
        # 推断：搏鱼拉力消息中形如 (0, 0, 1, X) 的浮点组，X 为鱼到玩家的出线距离（米）。
        # 实测 67 条鱼 520 个采样，X 收竿时收敛到 ~2 米，故判定为距离而非体力。出线无上限。
        for group in groups:
            if len(group) >= 4 and abs(group[0]) < 0.001 and abs(group[1]) < 0.001 and abs(group[2] - 1.0) < 0.001:
                return group[3]
        return None

    @staticmethod
    def _fight_stamina(groups: Tuple[Tuple[float, ...], ...]) -> Optional[int]:
        # 实测确认：搏鱼拉力帧浮点组第 2 组首位为鱼体力(1.0 满, 0.1 力竭)。
        # 转百分比 (v-0.1)/0.9*100 并钳制 0~100；越界(非体力)返回 None。
        if len(groups) < 2 or not groups[1]:
            return None
        stamina = groups[1][0]
        if not (0.05 <= stamina <= 1.05):
            return None
        percent = (stamina - 0.1) / 0.9 * 100
        return int(max(0, min(100, round(percent))))

    @staticmethod
    def _is_valid_distance(value: float) -> bool:
        # 出线无上限；0/负值为搏鱼起始阶段的瞬时抖动，NaN 为解析失败，应过滤。
        return not (value != value) and value > 0

    @staticmethod
    def _sanitize_distance(value: Optional[float], last: Optional[float]) -> Optional[float]:
        if value is not None and RF4ChatBridge._is_valid_distance(value):
            return value
        return last

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

        # 装备槽位请求(11/x)：登记 call_id→子命令，供服务器响应时反查槽位内容。
        if (
            envelope.marker == -1
            and envelope.main_cmd == 11
            and envelope.sub_cmd is not None
        ):
            session.slot_request_calls[envelope.call_id] = envelope.sub_cmd
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"slot_request sub={envelope.sub_cmd} payload={self._hex_preview(envelope.payload, limit=96)}"
                )

        # 结束钓鱼(14/4)请求：登记 call_id→请求，供服务器响应时反查鱼名/重量。
        fishing_end_request = parse_fishing_end_request(envelope, session.profile)
        if fishing_end_request:
            meta = self._fish_setup_meta_for_request(session, fishing_end_request)
            if meta and not fishing_end_request.fish_setup_id:
                fishing_end_request = FishingEndRequest(
                    call_id=fishing_end_request.call_id,
                    fishing_gear_id=fishing_end_request.fishing_gear_id,
                    fish_setup_id=meta.fish_setup_id,
                )
            session.fishing_end_requests[fishing_end_request.call_id] = fishing_end_request
            return plain_body, []

        # 记录抛竿动作：用钓组ID反查快捷键槽位，便于后续显示竿号。
        if envelope.main_cmd == session.profile.fishing_main_cmd and envelope.sub_cmd in (
            session.profile.cast_sub_cmd,
            session.profile.cast_prepare_sub_cmd,
        ):
            cast_gear = parse_fishing_gear_and_setup(envelope, session.profile, envelope.sub_cmd)
            if cast_gear and cast_gear.fishing_gear_id:
                if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                    self._log(
                        f"cast 钓组={self._short_id(cast_gear.fishing_gear_id)} "
                        f"sub={envelope.sub_cmd}"
                    )

        # 搏鱼拉力(14/8)：记录该钓组当前出线距离(过滤瞬时负值/超限)，供拉线动作/搏鱼关联展示。
        fight_load = parse_fishing_gear_and_setup(envelope, session.profile, session.profile.fight_load_sub_cmd)
        if fight_load and fight_load.fishing_gear_id:
            groups = self._scan_float_groups(envelope.payload, limit=8)
            distance = self._sanitize_distance(
                self._fight_distance(groups),
                session.fight_distance_by_gear.get(fight_load.fishing_gear_id),
            )
            if distance is not None:
                session.fight_distance_by_gear[fight_load.fishing_gear_id] = distance
            if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                self._log(
                    f"fight_load 钓组={self._short_id(fight_load.fishing_gear_id)} "
                    f"出线={self._format_float(distance) if distance is not None else '?'}米 "
                    f"hex={self._hex_preview(envelope.payload, limit=160)}"
                )
            return plain_body, []

        # 进入搏鱼阶段(14/11)：客户端确认鱼已挂牢咬钩，触发"确认咬钩"事件。
        fight_stage = parse_fishing_gear_and_setup(envelope, session.profile, session.profile.fight_stage_sub_cmd)
        if fight_stage and fight_stage.fish_setup_id:
            meta = session.fish_setup_cache.get(fight_stage.fish_setup_id)
            if fight_stage.fishing_gear_id:
                session.fight_fish_by_gear[fight_stage.fishing_gear_id] = fight_stage.fish_setup_id
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
            # 只有当该鱼确实经历过 14/14 来鱼推送（announced）时才显示放生，
            # 避免把监控启动前就在搏鱼的旧鱼误报。旧版本无 14/4 结算追踪，
            # 14/6 到达时 id 仍在 announced 中，故能正常显示；
            # 不再提前 discard 后即恢复该行为。
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

        # 4/22 装备/物品状态推送：学习 item_guid→item_id 映射，供槽位反查杆子型号。
        if envelope.marker == -1 and envelope.main_cmd == 4 and envelope.sub_cmd == 22:
            try:
                self._remember_gear_item_guids(session, envelope.payload)
            except Exception:
                pass

        # game/configs 1/5：客户端启动时请求的配置版本 hash 列表，用于解密本地配置缓存
        # (c0001.dat) 得到 configId→systemId 映射，从而把 4/22 的 itemId 翻译成装备中文名。
        if (
            envelope.marker == -1
            and envelope.main_cmd == session.profile.session_main_cmd
            and envelope.sub_cmd == 5
        ):
            try:
                self._remember_config_version_hashes(session, envelope.payload)
            except Exception:
                pass

        if envelope.marker == -2:
            tracked = session.rpc_request_commands.get(envelope.call_id)
            if tracked and tracked[0] == session.profile.session_main_cmd and tracked[1] == 5:
                try:
                    self._remember_config_version_hashes(session, envelope.payload)
                except Exception:
                    pass
            session.building_request_calls.pop(envelope.call_id, None)
            session.rpc_request_commands.pop(envelope.call_id, None)
            session.slot_request_calls.pop(envelope.call_id, None)

        fish_setup = parse_fish_setup_push(envelope, session.profile)
        if fish_setup:
            session.fish_setup_cache[fish_setup.fish_setup_id] = fish_setup
            # 记录 钓组→鱼编号 反查表：14/4 结算请求可能不带 setup_id，用钓组ID补全。
            if fish_setup.fishing_gear_id:
                session.fish_setup_by_gear[fish_setup.fishing_gear_id] = fish_setup.fish_setup_id
            # 详细记录来鱼推送的字段，用于确认竿位编号(gear slot)的来源。
            if self._room_protocol_details_enabled() or ctx.options.rf4_verbose_logging:
                extra = ""
                if fish_setup.extra_floats:
                    extra = " 浮动组=" + ", ".join(
                        f"{value:.4f}" for value in fish_setup.extra_floats
                    )
                flag = " 标记位=" + ("true" if fish_setup.flag_byte else "false") if fish_setup.flag_byte is not None else ""
                self._log(
                    f"fish_setup_push 钓组={self._short_id(fish_setup.fishing_gear_id)} "
                    f"鱼编号={self._short_id(fish_setup.fish_setup_id)} "
                    f"鱼名key={fish_setup.fish_key} setup_enum={fish_setup.setup_enum} "
                    f"长度={fish_setup.length_hint} 重量raw={fish_setup.weight_hint_raw}"
                    f"{extra}{flag}"
                    f" hex={self._hex_preview(envelope.payload, limit=160)}"
                )
            if (
                fish_setup.weight_hint_raw
                and fish_setup.fish_setup_id not in session.announced_fish_setup_ids
            ):
                session.announced_fish_setup_ids.add(fish_setup.fish_setup_id)
                synthetic = self._build_self_synthetic_event(
                    session=session,
                    fish_key=fish_setup.fish_key,
                    weight_raw=fish_setup.weight_hint_raw,
                    phase=self.SELF_EVENT_PHASE_INCOMING,
                    fishing_gear_id=fish_setup.fishing_gear_id,
                    fish_setup_id=fish_setup.fish_setup_id,
                    grade_enum=fish_setup.setup_enum,
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

        fishing_end_request = session.fishing_end_requests.pop(envelope.call_id, None)
        if fishing_end_request and envelope.marker == -2:
            # 不要在此处从 announced_fish_setup_ids 移除该鱼：14/4 结算响应总是先于
            # 随后的 14/5 入护 / 14/6 放生请求到达，提前 discard 会让放生/脱钩事件
            # 因为已不在 announced 集合而被跳过（旧版本无 14/4 追踪故正常）。
            # 由 14/5、14/6、14/12 各自的消费逻辑负责清理。
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

    def _remember_server_slot_items(self, session: FlowSession, plain_body: bytes, sub_cmd: Optional[int] = None) -> None:
        envelope = parse_envelope(plain_body)
        if envelope is None or envelope.marker != -2:
            return
        if envelope.call_id not in session.slot_request_calls:
            return
        try:
            slots = parse_slot_items_response_payload(envelope.payload)
        except Exception:
            return
        if not slots:
            return
        # 11/1(请求当前装备槽位)响应包含完整快捷键槽位映射，可更新 slot_items 反查竿号。
        shortcut_numbers = session.profile.shortcut_slot_numbers
        if sub_cmd == 2:
            # 11/2(切换装备槽位)单条响应：玩家切到快捷键槽 N 时携带该槽当前内容，
            # 是中途换杆后唯一的槽位更新来源，必须采纳，否则换杆后新竿永远没有
            # 竿号（映射停留在登录时的旧钓组上）。
            # slot_type=4 是"当前活动位"噪声(占绝大多数)，不可翻译成竿号，仍忽略。
            for slot in slots:
                if slot.slot_type in shortcut_numbers:
                    session.slot_items[slot.slot_type] = slot.item_guid
            return
        for slot in slots:
            session.slot_items[slot.slot_type] = slot.item_guid

    def _gear_slot_text(self, session: FlowSession, fishing_gear_id: Optional[str]) -> str:
        if not fishing_gear_id:
            return ""
        # 竿号来自 slot_items 映射（11/1 完整映射 + 11/2 单槽增量更新）。
        # slot_type 经 profile.shortcut_slot_numbers 翻译成竿号；
        # 未收录的类型不显示竿号，并记 verbose 日志便于补全映射。
        for slot_type, item_guid in session.slot_items.items():
            if item_guid == fishing_gear_id:
                rod_number = session.profile.shortcut_slot_numbers.get(slot_type)
                if rod_number is None:
                    if ctx.options.rf4_verbose_logging:
                        self._log(
                            f"未收录槽位类型 slot_type={slot_type} "
                            f"gear={self._short_id(fishing_gear_id)}"
                        )
                    return ""
                return f"{rod_number}号杆"
        return ""

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
        grade_hint = meta.setup_enum if (meta and meta.setup_enum is not None) else None

        if not fish_key or not weight_raw or not grade_hint:
            catch = extract_catch_summary_from_response(plain_body)
            if not fish_key:
                fish_key = catch.fish_key
            if not weight_raw:
                weight_raw = catch.weight_raw
            if not grade_hint:
                grade_hint = catch.size_enum

        if not fish_key or not weight_raw:
            return None

        return self._build_self_synthetic_event(
            session=session,
            fish_key=fish_key,
            weight_raw=weight_raw,
            phase=self.SELF_EVENT_PHASE_KEPT,
            fishing_gear_id=keep_request.fishing_gear_id,
            fish_setup_id=keep_request.fish_setup_id,
            grade_enum=grade_hint,
        )

    def _build_self_synthetic_event(
        self,
        session: FlowSession,
        fish_key: str,
        weight_raw: int,
        phase: str,
        fishing_gear_id: Optional[str] = None,
        fish_setup_id: Optional[str] = None,
        grade_enum: Optional[int] = None,
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

        # 等级枚举缺失时，回退到缓存的来鱼钓组字段（入护响应可能不含规格）。
        if grade_enum is None and fish_setup_id:
            meta = session.fish_setup_cache.get(fish_setup_id)
            if meta:
                grade_enum = meta.setup_enum

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
            grade_enum=grade_enum,
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

    def _write_emit_probe(self, text: str) -> None:
        try:
            import os
            with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "emit_probe.txt"), "a", encoding="utf-8") as f:
                f.write(f"{text}\n")
        except Exception:
            pass

    def _emit_self_event(self, session: FlowSession, synthetic: SyntheticChatEvent) -> bytes:
        # 日志始终全量输出；只有浮窗广播受勾选开关控制。
        self._write_emit_probe(
            f"{synthetic.phase}|{synthetic.fish_key}|bridge={self.__class__.__module__}.{self.__class__.__qualname__}"
        )
        self._log_self_event(self._format_self_event_log_line(synthetic))
        self._broadcast_self_event(synthetic)
        if not self._self_phase_enabled(synthetic.phase):
            return b""
        if not self._self_chat_injection_enabled():
            return b""
        if synthetic.phase in {self.SELF_EVENT_PHASE_ESCAPED, self.SELF_EVENT_PHASE_RELEASED}:
            return b""
        return self._inject_self_synthetic_event(session, synthetic)

    def _self_phase_enabled(self, phase: str) -> bool:
        phase_switch = {
            "incoming": "rf4_show_incoming",
            "bitten": "rf4_show_bitten",
            "kept": "rf4_show_kept",
            "escaped": "rf4_show_escaped",
            "released": "rf4_show_released",
        }.get(phase)
        if not phase_switch:
            return True
        return self._show_enabled(phase_switch)

    def _broadcast_self_event(self, synthetic: SyntheticChatEvent) -> None:
        try:
            self._broadcast_self_event_impl(synthetic)
        except Exception as e:
            self._write_emit_probe(f"broadcast_exc|{type(e).__name__}|{e}")

    def _broadcast_self_event_impl(self, synthetic: SyntheticChatEvent) -> None:
        port = int(getattr(ctx.options, "rf4_event_bridge_port", 0) or 0)
        if port <= 0:
            self._log(f"[广播]跳过: port={getattr(ctx.options, 'rf4_event_bridge_port', 0)!r}")
            return
        phase_switch = {
            self.SELF_EVENT_PHASE_INCOMING: "rf4_show_incoming",
            self.SELF_EVENT_PHASE_BITTEN: "rf4_show_bitten",
            self.SELF_EVENT_PHASE_KEPT: "rf4_show_kept",
            self.SELF_EVENT_PHASE_ESCAPED: "rf4_show_escaped",
            self.SELF_EVENT_PHASE_RELEASED: "rf4_show_released",
        }.get(synthetic.phase)
        if phase_switch and not self._show_enabled(phase_switch):
            self._log(f"[广播]被显示开关过滤 {phase_switch}")
            return
        fish_name = self._format_fish_name(synthetic.fish_key or "")
        grade_label = self._format_grade_enum(synthetic.grade_enum) or ""
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
                "grade_enum": synthetic.grade_enum,
                "grade_label": grade_label,
                "text": self._format_self_event_log_line(synthetic),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                host = getattr(ctx.options, "rf4_event_bridge_host", None) or "127.0.0.1"
                sock.sendto(payload.encode("utf-8"), (host, port))
                self._log(f"[广播]已发送 {event_name} -> {host}:{port} 字节={len(payload)}")
            finally:
                sock.close()
        except OSError:
            self._log(
                f"[广播]发送失败 {event_name} -> {getattr(ctx.options, 'rf4_event_bridge_host', None) or '127.0.0.1'}:{port}"
            )

    def broadcast_reset(self) -> None:
        """Broadcast a session-start reset so the overlay clears stale rows.

        Called once per new realtime handshake; the overlay responds by
        dropping every gear/telemetry row so old fishing state does not
        survive a reconnect (小退/重连).
        """
        self._broadcast_generic_event("reset", "")

    def _broadcast_generic_event(self, event_name: str, text: str) -> None:
        """广播其他事件(频道鱼获/公共聊天等)到浮窗，受显示设置勾选控制。"""
        port = int(getattr(ctx.options, "rf4_event_bridge_port", 0) or 0)
        if port <= 0:
            return
        switch = {
            "fish_catch": "rf4_show_catch_broadcast",
            "chat": "rf4_show_chat_broadcast",
        }.get(event_name)
        if switch and not self._show_enabled(switch):
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
                host = getattr(ctx.options, "rf4_event_bridge_host", None) or "127.0.0.1"
                sock.sendto(payload.encode("utf-8"), (host, port))
            finally:
                sock.close()
        except OSError:
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"failed to broadcast {event_name} on {getattr(ctx.options, 'rf4_event_bridge_host', None) or '127.0.0.1'}:{port}"
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
        fish_name = self._format_graded_fish_name(event.fish_key, event.grade_enum)
        weight = self._format_chat_weight(event.weight_raw)
        prefix = f"[{event.gear_slot_text}]" if event.gear_slot_text else ""
        if event.phase == self.SELF_EVENT_PHASE_INCOMING:
            return f"【我自己】：{prefix} 有{fish_name} {weight} 过来了"
        if event.phase == self.SELF_EVENT_PHASE_BITTEN:
            return f"【我自己】：{prefix} {fish_name} {weight} 咬钩了"
        if event.phase == self.SELF_EVENT_PHASE_ESCAPED:
            return f"【我自己】：{prefix} {fish_name} {weight} 挣脱跑了（脱钩）"
        if event.phase == self.SELF_EVENT_PHASE_RELEASED:
            return f"【我自己】：{prefix} 放生了 {fish_name}" if fish_name else f"【我自己】：{prefix} 放生了"
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
        return self._format_grade_enum(self._fish_grade_by_line_type.get(line_type))

    def _format_grade_enum(self, grade_enum: Optional[int]) -> Optional[str]:
        if grade_enum is None:
            return None
        return self._fish_grade_labels.get(grade_enum)

    def _format_graded_fish_name(self, fish_key: str, grade_enum: Optional[int]) -> str:
        fish_name = self._format_fish_name(fish_key)
        grade = self._format_grade_enum(grade_enum)
        return f"[{grade}] {fish_name}" if grade else fish_name

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
