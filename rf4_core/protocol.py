from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class RF4ProtocolProfile:
    name: str
    session_main_cmd: int
    player_main_cmd: int
    server_player_main_cmd: int
    feeding_main_cmd: int
    fishing_main_cmd: int
    cast_prepare_sub_cmd: int
    cast_sub_cmd: int
    fall_sub_cmd: int
    fishing_end_sub_cmd: int
    fish_setup_push_sub_cmd: int
    keep_fish_sub_cmd: int
    release_fish_sub_cmd: int
    fight_step_sub_cmd: int
    fight_load_sub_cmd: int
    fight_pull_sub_cmd: int
    fish_gen_sub_cmd: int
    fight_stage_sub_cmd: int
    contact_left_sub_cmd: int
    fish_sync_push_sub_cmd: int
    social_main_cmd: int
    public_chat_sub_cmd: int
    room_message_push_sub_cmd: int
    room_message_ack_sub_cmd: int
    room_message_object_type_id: int
    room_detail_item_type_id: int
    room_ack_profile_type_id: int
    room_message_line_type_catch: int
    arg_list_code: bytes = b"507"
    detail_list_code: bytes = b"135"


RF4_4_0_24799 = RF4ProtocolProfile(
    name="4.0.24799",
    session_main_cmd=1,
    player_main_cmd=3,
    server_player_main_cmd=2,
    feeding_main_cmd=12,
    fishing_main_cmd=14,
    cast_prepare_sub_cmd=1,
    cast_sub_cmd=2,
    fall_sub_cmd=3,
    fishing_end_sub_cmd=4,
    fish_setup_push_sub_cmd=14,
    keep_fish_sub_cmd=5,
    release_fish_sub_cmd=6,
    fight_step_sub_cmd=7,
    fight_load_sub_cmd=8,
    fight_pull_sub_cmd=9,
    fish_gen_sub_cmd=10,
    fight_stage_sub_cmd=11,
    contact_left_sub_cmd=12,
    fish_sync_push_sub_cmd=15,
    social_main_cmd=24,
    public_chat_sub_cmd=10,
    room_message_push_sub_cmd=27,
    room_message_ack_sub_cmd=19,
    room_message_object_type_id=401,
    room_detail_item_type_id=400,
    room_ack_profile_type_id=2002,
    room_message_line_type_catch=3,
)


KNOWN_PROFILES: Dict[str, RF4ProtocolProfile] = {
    RF4_4_0_24799.name: RF4_4_0_24799,
}


def get_profile(name: str) -> RF4ProtocolProfile:
    try:
        return KNOWN_PROFILES[name]
    except KeyError as exc:
        known = ", ".join(sorted(KNOWN_PROFILES))
        raise ValueError(f"unknown RF4 profile '{name}', expected one of: {known}") from exc

# --- Binary protocol codec ---
import re
import struct
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union


UUID_RE = re.compile(
    rb"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)


def u16(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "little", signed=False)


def u32(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 4], "little", signed=False)


def u64(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 8], "little", signed=False)


def pack_u16(value: int) -> bytes:
    return struct.pack("<H", value)


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def pack_u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def guid_le(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw))


def pack_guid_marker(value: str) -> bytes:
    return b"\x0c" + uuid.UUID(value).bytes_le


def pack_guid_raw(value: str) -> bytes:
    return uuid.UUID(value).bytes_le


def read_short_string(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    if pos >= len(data):
        return None, pos
    if data[pos] == 0xFF:
        return None, pos + 1
    size = data[pos]
    pos += 1
    return data[pos:pos + size].decode("utf-8", errors="replace"), pos + size


def read_marked_string(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    if pos >= len(data):
        return None, pos
    if data[pos] == 0xFF:
        return None, pos + 1
    if data[pos] != 0x14:
        raise ValueError(f"expected 0x14 string marker at {pos}, got 0x{data[pos]:02x}")
    return read_short_string(data, pos + 1)


def read_flexible_string(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    if pos >= len(data):
        return None, pos
    if data[pos] in (0x14, 0xFF):
        return read_marked_string(data, pos)
    return read_short_string(data, pos)


def pack_short_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("short string exceeds 255 bytes")
    return bytes([len(raw)]) + raw


def pack_marked_string(value: str) -> bytes:
    return b"\x14" + pack_short_string(value)


def pack_marked_u32(value: int) -> bytes:
    return b"\x10" + pack_u32(value)


def pack_arg_header(type_code: bytes, count: int) -> bytes:
    if len(type_code) > 255:
        raise ValueError("type code exceeds 255 bytes")
    return b"\x03" + bytes([len(type_code)]) + type_code + pack_u16(count)


def read_arg_header(data: bytes, pos: int) -> Tuple[int, int]:
    if pos + 4 > len(data) or data[pos] != 0x03:
        raise ValueError("missing typed arg header")
    size = data[pos + 1]
    start = pos + 2
    end = start + size
    if end + 2 > len(data):
        raise ValueError("truncated typed arg header")
    return u16(data, end), end + 2


def pack_object_header(type_id: int) -> bytes:
    return b"\x01" + pack_u32(type_id)


def read_object_header(data: bytes, pos: int) -> Tuple[int, int]:
    if pos + 5 > len(data) or data[pos] != 0x01:
        raise ValueError(f"missing object marker at {pos}")
    return u32(data, pos + 1), pos + 5


def read_guid(data: bytes, pos: int, marker: bool) -> Tuple[str, int]:
    if marker:
        if pos >= len(data) or data[pos] != 0x0C:
            raise ValueError(f"missing guid marker at {pos}")
        pos += 1
    if pos + 16 > len(data):
        raise ValueError("truncated guid")
    return guid_le(data[pos:pos + 16]), pos + 16


def ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    out: List[str] = []
    buf: List[str] = []
    for value in data:
        if 32 <= value < 127:
            buf.append(chr(value))
        else:
            if len(buf) >= min_len:
                out.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        out.append("".join(buf))
    return out


def plausible_fish_key(value: str) -> bool:
    if value.startswith(("level_", "rig_", "tele_", "worm_", "bait_", "dough_", "nav", "loc")):
        return False
    if value in {"test233"} or "@" in value or "[" in value or "]" in value:
        return False
    return bool(re.fullmatch(r"[a-z][a-z0-9_.]*", value))


def windows_filetime_now() -> int:
    return int((time.time() + 11644473600) * 10000000)


@dataclass(frozen=True)
class AppFrame:
    raw: bytes
    body_len: int
    frame_type: int
    wire_id: int
    payload: bytes

    @property
    def is_zero_marker(self) -> bool:
        return self.body_len == 0


@dataclass(frozen=True)
class RpcEnvelope:
    marker: int
    call_id: int
    main_cmd: Optional[int]
    sub_cmd: Optional[int]
    payload: bytes


@dataclass(frozen=True)
class FishSetupMeta:
    fish_setup_id: str
    fish_key: str
    fishing_gear_id: Optional[str] = None
    setup_enum: Optional[int] = None
    weight_hint_raw: Optional[int] = None
    length_hint: Optional[float] = None


@dataclass(frozen=True)
class KeepFishRequest:
    call_id: int
    fishing_gear_id: Optional[str]
    fish_setup_id: Optional[str]


@dataclass(frozen=True)
class PublicChatRequest:
    call_id: int
    message: Optional[str]


@dataclass(frozen=True)
class CatchSummary:
    fish_key: Optional[str]
    weight_raw: Optional[int]
    size_enum: Optional[int] = None


@dataclass(frozen=True)
class RoomDetailItem:
    slot: int
    kind: str
    value: Optional[Union[str, int]]


@dataclass(frozen=True)
class RoomBroadcast:
    line_type: int
    event_id: int
    fish_key: Optional[str]
    weight_raw: Optional[int]
    location_id: Optional[str]
    users_count: Optional[int]
    details: Tuple[RoomDetailItem, ...] = ()


@dataclass(frozen=True)
class RoomAckRequest:
    event_id: Optional[int]


@dataclass(frozen=True)
class RoomAckResponse:
    event_id: Optional[int]
    sender_name: Optional[str]
    avatar_url: Optional[str]
    sender_rank: Optional[int]


@dataclass(frozen=True)
class BusinessPayloadSummary:
    arg_count: Optional[int]
    strings: Tuple[str, ...]
    guids: Tuple[str, ...]
    u32_values: Tuple[int, ...]
    float_groups: Tuple[Tuple[float, ...], ...]


class RC4Stream:
    def __init__(self, key: bytes):
        if not key:
            raise ValueError("RC4 key must not be empty")
        self._s = list(range(256))
        self._i = 0
        self._j = 0
        j = 0
        key_bytes = list(key)
        for i in range(256):
            j = (j + self._s[i] + key_bytes[i % len(key_bytes)]) & 0xFF
            self._s[i], self._s[j] = self._s[j], self._s[i]

    def keystream(self, size: int) -> bytes:
        out = bytearray()
        s = self._s
        i = self._i
        j = self._j
        for _ in range(size):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out.append(s[(s[i] + s[j]) & 0xFF])
        self._i = i
        self._j = j
        return bytes(out)

    def crypt(self, data: bytes) -> bytes:
        return xor_bytes(data, self.keystream(len(data)))


def try_parse_auth_packet(data: bytes) -> Optional[Tuple[str, int]]:
    if len(data) < 6 or data[:2] != b"\x01\x00":
        return None
    token_len = u32(data, 2)
    total = 6 + token_len
    if token_len <= 0 or len(data) < total:
        return None
    token = data[6:total].decode("utf-8", errors="strict")
    if token.count("|") < 3:
        return None
    return token, total


def try_parse_uuid_packet(data: bytes) -> Optional[Tuple[str, int]]:
    if len(data) < 36:
        return None
    candidate = data[:36]
    if not UUID_RE.match(candidate):
        return None
    return candidate.decode("ascii"), 36


def try_parse_first_frame(data: bytes) -> Optional[AppFrame]:
    if len(data) < 4:
        return None
    body_len = u32(data, 0)
    if body_len == 0:
        return AppFrame(raw=data[:4], body_len=0, frame_type=0, wire_id=0, payload=b"")
    if body_len == 1:
        if len(data) < 5:
            return None
        return AppFrame(raw=data[:5], body_len=1, frame_type=data[4], wire_id=0, payload=b"")
    if body_len < 9:
        raise ValueError(f"invalid body_len {body_len}")
    if len(data) < 13:
        return None
    total = 4 + body_len
    if len(data) < total:
        return None
    frame_type = data[4]
    wire_id = u64(data, 5)
    raw = data[:total]
    payload = data[13:total]
    return AppFrame(raw=raw, body_len=body_len, frame_type=frame_type, wire_id=wire_id, payload=payload)


def take_complete_frames(buffer: bytearray) -> List[AppFrame]:
    frames: List[AppFrame] = []
    while True:
        frame = try_parse_first_frame(buffer)
        if frame is None:
            break
        frames.append(frame)
        del buffer[:len(frame.raw)]
    return frames


def build_frame(frame_type: int, wire_id: int, payload: bytes) -> bytes:
    body_len = 9 + len(payload)
    return pack_u32(body_len) + bytes([frame_type]) + pack_u64(wire_id) + payload


def build_ack_frame(wire_id: int) -> bytes:
    return build_frame(1, wire_id, b"")


def parse_envelope(plain_body: bytes) -> Optional[RpcEnvelope]:
    if len(plain_body) < 9 or plain_body[0] != 0x01:
        return None
    marker = int.from_bytes(plain_body[1:5], "little", signed=True)
    if marker not in (-1, -2):
        return None
    call_id = u32(plain_body, 5)
    if marker == -1:
        if len(plain_body) < 11:
            return None
        return RpcEnvelope(
            marker=marker,
            call_id=call_id,
            main_cmd=plain_body[9],
            sub_cmd=plain_body[10],
            payload=plain_body[11:],
        )
    return RpcEnvelope(marker=marker, call_id=call_id, main_cmd=None, sub_cmd=None, payload=plain_body[9:])


def build_request_envelope(call_id: int, main_cmd: int, sub_cmd: int, payload: bytes) -> bytes:
    return b"\x01" + struct.pack("<iI", -1, call_id) + bytes([main_cmd, sub_cmd]) + payload


def build_response_envelope(call_id: int, payload: bytes) -> bytes:
    return b"\x01" + struct.pack("<iI", -2, call_id) + payload


def parse_fish_setup_push(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[FishSetupMeta]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.fishing_main_cmd or envelope.sub_cmd != profile.fish_setup_push_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        fishing_gear_id, pos = read_guid(envelope.payload, pos, marker=True)
        _, pos = read_object_header(envelope.payload, pos)
        fish_setup_id, pos = read_guid(envelope.payload, pos, marker=False)
        fish_key, pos = read_short_string(envelope.payload, pos)
        setup_enum = None
        length_hint = None
        weight_hint_raw = None
        if pos < len(envelope.payload):
            setup_enum = envelope.payload[pos]
            pos += 1
        if pos + 4 <= len(envelope.payload):
            length_hint = struct.unpack_from("<f", envelope.payload, pos)[0]
            pos += 4
        if pos + 4 <= len(envelope.payload):
            weight_hint_raw = u32(envelope.payload, pos)
    except (ValueError, IndexError):
        return None
    if not fish_key:
        return None
    return FishSetupMeta(
        fish_setup_id=fish_setup_id,
        fish_key=fish_key,
        fishing_gear_id=fishing_gear_id,
        setup_enum=setup_enum,
        weight_hint_raw=weight_hint_raw,
        length_hint=length_hint,
    )


def parse_keep_fish_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[KeepFishRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.fishing_main_cmd or envelope.sub_cmd != profile.keep_fish_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        fishing_gear_id = None
        fish_setup_id = None
        if pos < len(envelope.payload) and envelope.payload[pos] == 0x0C:
            fishing_gear_id, pos = read_guid(envelope.payload, pos, marker=True)
        if pos < len(envelope.payload) and envelope.payload[pos] == 0x0C:
            fish_setup_id, pos = read_guid(envelope.payload, pos, marker=True)
    except (ValueError, IndexError):
        return None
    return KeepFishRequest(
        call_id=envelope.call_id,
        fishing_gear_id=fishing_gear_id,
        fish_setup_id=fish_setup_id,
    )


def parse_fishing_gear_and_setup(envelope: RpcEnvelope, profile: RF4ProtocolProfile, sub_cmd: int) -> Optional[KeepFishRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.fishing_main_cmd or envelope.sub_cmd != sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        fishing_gear_id = None
        fish_setup_id = None
        if pos < len(envelope.payload) and envelope.payload[pos] == 0x0C:
            fishing_gear_id, pos = read_guid(envelope.payload, pos, marker=True)
        if pos < len(envelope.payload) and envelope.payload[pos] == 0x0C:
            fish_setup_id, pos = read_guid(envelope.payload, pos, marker=True)
    except (ValueError, IndexError):
        return None
    return KeepFishRequest(
        call_id=envelope.call_id,
        fishing_gear_id=fishing_gear_id,
        fish_setup_id=fish_setup_id,
    )


def parse_contact_left(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[KeepFishRequest]:
    return parse_fishing_gear_and_setup(envelope, profile, profile.contact_left_sub_cmd)


def parse_release_fish_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[KeepFishRequest]:
    return parse_fishing_gear_and_setup(envelope, profile, profile.release_fish_sub_cmd)


def parse_public_chat_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[PublicChatRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.social_main_cmd or envelope.sub_cmd != profile.public_chat_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        message, _ = read_flexible_string(envelope.payload, pos)
    except (ValueError, IndexError):
        return None
    return PublicChatRequest(call_id=envelope.call_id, message=message)


def extract_catch_summary_from_response(plain_body: bytes) -> CatchSummary:
    strings = ascii_strings(plain_body)
    fish_key = None
    for value in strings:
        if plausible_fish_key(value):
            fish_key = value
            break
    if not fish_key:
        return CatchSummary(fish_key=None, weight_raw=None, size_enum=None)

    needle = bytes([len(fish_key)]) + fish_key.encode("utf-8")
    idx = plain_body.find(needle)
    if idx < 0:
        return CatchSummary(fish_key=fish_key, weight_raw=None, size_enum=None)

    pos = idx + len(needle)
    weight_raw = None
    size_enum = None
    if pos + 4 <= len(plain_body):
        candidate = u32(plain_body, pos)
        if 0 < candidate < 10000000:
            weight_raw = candidate
    if pos + 10 <= len(plain_body):
        candidate = u16(plain_body, pos + 8)
        if 0 < candidate < 256:
            size_enum = candidate
    return CatchSummary(fish_key=fish_key, weight_raw=weight_raw, size_enum=size_enum)


def parse_room_broadcast(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[RoomBroadcast]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.social_main_cmd or envelope.sub_cmd != profile.room_message_push_sub_cmd:
        return None

    data = envelope.payload
    try:
        _, pos = read_arg_header(data, 0)
        _, pos = read_object_header(data, pos)
        line_type = data[pos]
        pos += 1
        pos += 2
        event_id = u32(data, pos)
        pos += 4
        pos += 8

        details: List[RoomDetailItem] = []
        if data[pos:pos + 5] == pack_arg_header(profile.detail_list_code, 0)[:5]:
            detail_count = u16(data, pos + 5)
            pos += 7
            for _ in range(detail_count):
                _, pos = read_object_header(data, pos)
                slot = data[pos]
                pos += 1
                marker = data[pos]
                if marker == 0x14:
                    value, pos = read_marked_string(data, pos)
                    details.append(RoomDetailItem(slot=slot, kind="string", value=value))
                elif marker == 0x10:
                    pos += 1
                    value = u32(data, pos)
                    pos += 4
                    details.append(RoomDetailItem(slot=slot, kind="u32", value=value))
                else:
                    break

        location_id = None
        if pos < len(data) and data[pos] == 0x14:
            location_id, pos = read_marked_string(data, pos)

        users_count = None
        if pos < len(data) and data[pos] == 0x10:
            users_count = u32(data, pos + 1)

        fish_key = None
        weight_raw = None
        for item in details:
            if item.slot == 1 and item.kind == "string":
                fish_key = item.value
            elif item.slot == 2 and item.kind == "u32":
                weight_raw = item.value

        return RoomBroadcast(
            line_type=line_type,
            event_id=event_id,
            fish_key=fish_key,
            weight_raw=weight_raw,
            location_id=location_id,
            users_count=users_count,
            details=tuple(details),
        )
    except (ValueError, IndexError):
        return None


def parse_room_ack_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[RoomAckRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.social_main_cmd or envelope.sub_cmd != profile.room_message_ack_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
    except (ValueError, IndexError):
        return None
    if pos + 5 <= len(envelope.payload) and envelope.payload[pos] == 0x10:
        return RoomAckRequest(event_id=u32(envelope.payload, pos + 1))
    return RoomAckRequest(event_id=None)


def parse_room_ack_response(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[RoomAckResponse]:
    if envelope.marker != -2:
        return None

    data = envelope.payload
    pos = 0
    if pos + 5 > len(data) or data[pos] != 0x08:
        return None
    pos += 5

    if pos + 5 > len(data) or data[pos] != 0x01:
        return None
    if u32(data, pos + 1) != profile.room_ack_profile_type_id:
        return None
    pos += 5

    if pos + 4 > len(data):
        return None
    event_id = u32(data, pos)
    pos += 4

    if pos >= len(data):
        return RoomAckResponse(
            event_id=event_id,
            sender_name=None,
            avatar_url=None,
            sender_rank=None,
        )

    name_len = data[pos]
    pos += 1
    if pos + name_len > len(data):
        return None
    sender_name = data[pos:pos + name_len].decode("utf-8", errors="replace")
    pos += name_len

    if pos < len(data) and data[pos] == 0x51:
        pos += 1
    if pos < len(data) and data[pos] == 0x00:
        pos += 1

    avatar_url = None
    if pos + 4 <= len(data) and data[pos:pos + 4] == b"http":
        end = data.find(b"\x00", pos)
        if end == -1:
            return None
        avatar_url = data[pos:end].decode("utf-8", errors="replace")
        pos = end + 1

    if pos < len(data) and data[pos] == 0x00 and pos + 15 <= len(data):
        pos += 1

    sender_rank = None
    if pos + 14 <= len(data):
        sender_rank = u32(data, pos)

    return RoomAckResponse(
        event_id=event_id,
        sender_name=sender_name or None,
        avatar_url=avatar_url,
        sender_rank=sender_rank,
    )


def build_room_message_push_body(
    profile: RF4ProtocolProfile,
    call_id: int,
    event_id: int,
    fish_key: str,
    weight_raw: int,
    location_id: str,
    users_count: int,
    message_time_raw: Optional[int] = None,
    line_type: Optional[int] = None,
) -> bytes:
    detail_items = bytearray()
    detail_items.extend(pack_object_header(profile.room_detail_item_type_id))
    detail_items.extend(b"\x01")
    detail_items.extend(pack_marked_string(fish_key))
    detail_items.extend(pack_object_header(profile.room_detail_item_type_id))
    detail_items.extend(b"\x02")
    detail_items.extend(pack_marked_u32(weight_raw))

    payload = bytearray()
    payload.extend(pack_arg_header(profile.arg_list_code, 3))
    payload.extend(pack_object_header(profile.room_message_object_type_id))
    payload.extend(bytes([line_type if line_type is not None else profile.room_message_line_type_catch]))
    payload.extend(b"\xff\xff")
    payload.extend(pack_u32(event_id))
    payload.extend(pack_u64(message_time_raw if message_time_raw is not None else windows_filetime_now()))
    payload.extend(pack_arg_header(profile.detail_list_code, 2))
    payload.extend(detail_items)
    payload.extend(pack_marked_string(location_id))
    payload.extend(pack_marked_u32(users_count))
    payload.extend(b"\x01")
    return build_request_envelope(
        call_id=call_id,
        main_cmd=profile.social_main_cmd,
        sub_cmd=profile.room_message_push_sub_cmd,
        payload=bytes(payload),
    )


def build_room_ack_response_body(
    profile: RF4ProtocolProfile,
    call_id: int,
    event_id: int,
    sender_name: str,
    avatar_url: str,
    sender_level: int,
    sender_region: int,
    sender_class: int,
    sender_badge: int,
) -> bytes:
    profile_block = bytearray()
    profile_block.extend(pack_object_header(profile.room_ack_profile_type_id))
    profile_block.extend(pack_u32(event_id))
    profile_block.extend(pack_short_string(sender_name))
    if avatar_url:
        profile_block.extend(b"\x51")
        profile_block.extend(avatar_url.encode("utf-8"))
        profile_block.extend(b"\x00")
    else:
        profile_block.extend(b"\x00")
    profile_block.extend(pack_u32(sender_level))
    profile_block.extend(pack_u32(sender_region))
    profile_block.extend(pack_u16(0x0401))
    profile_block.extend(pack_u16(sender_class))
    profile_block.extend(pack_u16(sender_badge))

    payload = b"\x08" + pack_u32(len(profile_block)) + bytes(profile_block)
    return build_response_envelope(call_id=call_id, payload=payload)

