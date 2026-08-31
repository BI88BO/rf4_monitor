from __future__ import annotations

from dataclasses import dataclass, field
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
    # 快捷键槽位类型 → 竿号。对照 GameAssembly.dll 验证：1/2/3 为前 3 竿，
    # 20/21/22/23 对应 4..7 竿。slot_type==4(当前活动位) 不在表中，避免误显"4号杆"。
    shortcut_slot_numbers: Dict[int, int] = field(default_factory=dict)


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
    shortcut_slot_numbers={1: 1, 2: 2, 3: 3, 20: 4, 21: 5, 22: 6, 23: 7},
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
import math
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


def i32(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 4], "little", signed=True)


def f32(data: bytes, pos: int) -> float:
    return struct.unpack_from("<f", data, pos)[0]


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


def _require_bytes(data: bytes, pos: int, size: int, label: str) -> None:
    if pos < 0 or size < 0 or pos + size > len(data):
        raise ValueError(f"truncated {label}")


def read_typed_list_header(data: bytes, pos: int) -> Optional[Tuple[str, int, int]]:
    if pos + 4 > len(data) or data[pos] != 0x03:
        return None
    size = data[pos + 1]
    start = pos + 2
    end = start + size
    if size <= 0 or end + 2 > len(data):
        return None
    try:
        type_code = data[start:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not type_code.isdigit():
        return None
    return type_code, u16(data, end), end + 2


def read_guid_array(data: bytes, pos: int, marker: bool = True) -> Tuple[Tuple[str, ...], int]:
    if marker:
        _require_bytes(data, pos, 1, "Guid array marker")
        if data[pos] != 0x06:
            raise ValueError(f"expected Guid array marker at {pos}")
        pos += 1
    _require_bytes(data, pos, 2, "Guid array count")
    count = u16(data, pos)
    pos += 2
    if count > 4096:
        raise ValueError("Guid array count is unreasonable")
    _require_bytes(data, pos, count * 16, "Guid array")
    values = tuple(
        guid_le(data[pos + index * 16:pos + (index + 1) * 16])
        for index in range(count)
    )
    return values, pos + count * 16


def read_phoenix_string(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    _require_bytes(data, pos, 1, "Phoenix string marker")
    marker = data[pos]
    if marker == 0xFF:
        return None, pos + 1
    widths = {0x14: 1, 0x15: 2, 0x16: 4}
    width = widths.get(marker)
    if width is None:
        raise ValueError(f"unsupported Phoenix string marker 0x{marker:02x}")
    _require_bytes(data, pos + 1, width, "Phoenix string length")
    size = int.from_bytes(data[pos + 1:pos + 1 + width], "little", signed=False)
    start = pos + 1 + width
    _require_bytes(data, start, size, "Phoenix string")
    return data[start:start + size].decode("utf-8", errors="replace"), start + size


def _read_nullable_short_string_strict(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    _require_bytes(data, pos, 1, "short string")
    if data[pos] == 0xFF:
        return None, pos + 1
    size = data[pos]
    start = pos + 1
    _require_bytes(data, start, size, "short string")
    return data[start:start + size].decode("utf-8", errors="replace"), start + size


def _read_money_pair_object(data: bytes, pos: int) -> Tuple[Tuple[int, int], int]:
    object_type_id, pos = read_object_header(data, pos)
    if object_type_id != 17497:
        raise ValueError(f"expected money pair type 17497, got {object_type_id}")
    _require_bytes(data, pos, 16, "money pair")
    silver_raw = int.from_bytes(data[pos:pos + 8], "little", signed=True)
    gold_raw = int.from_bytes(data[pos + 8:pos + 16], "little", signed=True)
    return (silver_raw, gold_raw), pos + 16


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


def _read_repair_request_object(data: bytes, pos: int) -> Tuple[RepairRequestSummary, int]:
    object_type_id, pos = read_object_header(data, pos)
    if object_type_id != 17510:
        raise ValueError(f"expected repair request type 17510, got {object_type_id}")
    item_guid, pos = read_guid(data, pos, marker=False)
    selections: List[RepairSelectionSummary] = []
    header = read_typed_list_header(data, pos)
    if header is None:
        if pos >= len(data) or data[pos] != 0xFF:
            raise ValueError("missing repair component list")
        pos += 1
    else:
        _, count, pos = header
        if count > 256:
            raise ValueError("repair component count is unreasonable")
        for _ in range(count):
            selection_type_id, pos = read_object_header(data, pos)
            if selection_type_id != 17509:
                raise ValueError(f"expected repair selection type 17509, got {selection_type_id}")
            _require_bytes(data, pos, 1, "repair component enum")
            component_type = data[pos]
            component_key, pos = _read_nullable_short_string_strict(data, pos + 1)
            selections.append(
                RepairSelectionSummary(
                    component_type=component_type,
                    component_key=component_key,
                )
            )
    _require_bytes(data, pos, 9, "repair request tail")
    option_enabled = bool(data[pos])
    quoted_cost_raw = int.from_bytes(data[pos + 1:pos + 9], "little", signed=True)
    return (
        RepairRequestSummary(
            item_guid=item_guid,
            selections=tuple(selections),
            option_enabled=option_enabled,
            quoted_cost_raw=quoted_cost_raw,
        ),
        pos + 9,
    )


def read_phoenix_argument(data: bytes, pos: int) -> Tuple[PhoenixArgument, int]:
    _require_bytes(data, pos, 1, "Phoenix argument")
    marker = data[pos]
    if marker in (0x14, 0x15, 0x16, 0xFF):
        value, next_pos = read_phoenix_string(data, pos)
        return PhoenixArgument(marker=marker, kind="string", value=value), next_pos
    if marker == 0x0C:
        value, next_pos = read_guid(data, pos, marker=True)
        return PhoenixArgument(marker=marker, kind="guid", value=value), next_pos
    if marker == 0x0D:
        _require_bytes(data, pos + 1, 4, "Int32 argument")
        return PhoenixArgument(marker=marker, kind="i32", value=i32(data, pos + 1)), pos + 5
    if marker in (0x0E, 0x0F):
        return PhoenixArgument(marker=marker, kind="bool", value=marker == 0x0E), pos + 1
    if marker == 0x10:
        _require_bytes(data, pos + 1, 4, "UInt32 argument")
        return PhoenixArgument(marker=marker, kind="u32", value=u32(data, pos + 1)), pos + 5
    if marker == 0x11:
        _require_bytes(data, pos + 1, 8, "Int64 argument")
        value = int.from_bytes(data[pos + 1:pos + 9], "little", signed=True)
        return PhoenixArgument(marker=marker, kind="i64", value=value), pos + 9
    if marker == 0x13:
        _require_bytes(data, pos + 1, 4, "Single argument")
        return PhoenixArgument(marker=marker, kind="f32", value=f32(data, pos + 1)), pos + 5
    if marker == 0x06:
        value, next_pos = read_guid_array(data, pos, marker=True)
        return PhoenixArgument(marker=marker, kind="guid_array", value=value), next_pos
    if marker == 0x01:
        object_type_id = u32(data, pos + 1) if pos + 5 <= len(data) else -1
        if object_type_id == 17510:
            value, next_pos = _read_repair_request_object(data, pos)
            return PhoenixArgument(marker=marker, kind="repair_request", value=value), next_pos
        raise ValueError(f"unsupported Phoenix argument object type {object_type_id}")
    raise ValueError(f"unsupported Phoenix argument marker 0x{marker:02x}")


def parse_typed_arguments(data: bytes) -> Tuple[PhoenixArgument, ...]:
    count, pos = read_arg_header(data, 0)
    if count > 256:
        raise ValueError("typed argument count is unreasonable")
    arguments: List[PhoenixArgument] = []
    for _ in range(count):
        argument, pos = read_phoenix_argument(data, pos)
        arguments.append(argument)
    return tuple(arguments)


def parse_observed_catch_records(data: bytes) -> Tuple[ObservedCatchRecord, ...]:
    needle = b"\x01\x19\x00\x00\x00"
    records: List[ObservedCatchRecord] = []
    pos = 0
    while len(records) < 512:
        offset = data.find(needle, pos)
        if offset < 0:
            break
        pos = offset + len(needle)
        try:
            fish_key, pos = _read_nullable_short_string_strict(data, pos)
            if not fish_key or not plausible_fish_key(fish_key):
                continue
            _require_bytes(data, pos, 18, "catch record prefix")
            weight_raw = u32(data, pos)
            pos += 4
            _ = f32(data, pos)
            pos += 4
            size_enum = u16(data, pos)
            pos += 2
            pos += 8
            if pos + 5 <= len(data) and data[pos] == 0x01 and u32(data, pos + 1) == 600:
                pos += 5
                _require_bytes(data, pos, 12, "catch metadata")
                pos += 12
            _require_bytes(data, pos, 1, "catch bait prefix")
            _, pos = _read_nullable_short_string_strict(data, pos + 1)
            _require_bytes(data, pos, 1, "catch level prefix")
            _, pos = _read_nullable_short_string_strict(data, pos + 1)
            _require_bytes(data, pos, 22, "catch record identity")
            pos += 6
            record_guid = guid_le(data[pos:pos + 16])
            pos += 16
            if 0 < weight_raw < 10_000_000 and record_guid != str(uuid.UUID(int=0)):
                records.append(
                    ObservedCatchRecord(
                        record_guid=record_guid,
                        fish_key=fish_key,
                        weight_raw=weight_raw,
                        size_enum=size_enum,
                    )
                )
        except (ValueError, IndexError, struct.error):
            pos = offset + 1
    unique = {record.record_guid: record for record in records}
    return tuple(unique.values())


def parse_fish_sale_results(data: bytes) -> Tuple[FishSaleResult, ...]:
    header = read_typed_list_header(data, 0)
    if header is None:
        return ()
    _, count, pos = header
    if count > 4096:
        return ()
    results: List[FishSaleResult] = []
    try:
        for _ in range(count):
            object_type_id, pos = read_object_header(data, pos)
            if object_type_id != 303:
                return ()
            fish_guid, pos = read_guid(data, pos, marker=False)
            _require_bytes(data, pos, 9, "fish sale result")
            paid_raw = int.from_bytes(data[pos:pos + 8], "little", signed=True)
            status = data[pos + 8]
            pos += 9
            results.append(FishSaleResult(fish_guid=fish_guid, paid_raw=paid_raw, status=status))
    except (ValueError, IndexError):
        return ()
    return tuple(results)


def parse_cafe_delivery_result(data: bytes) -> Optional[Tuple[int, int]]:
    try:
        object_type_id, pos = read_object_header(data, 0)
        if object_type_id != 300:
            return None
        _require_bytes(data, pos, 9, "cafe delivery result")
        reward_raw = int.from_bytes(data[pos:pos + 8], "little", signed=True)
        return reward_raw, data[pos + 8]
    except (ValueError, IndexError):
        return None


def parse_workshop_diagnosis(data: bytes) -> Optional[WorkshopDiagnosisSummary]:
    try:
        object_type_id, pos = read_object_header(data, 0)
        if object_type_id != 503:
            return None
        item_guid, pos = read_guid(data, pos, marker=False)
        header = read_typed_list_header(data, pos)
        if header is None:
            return WorkshopDiagnosisSummary(item_guid=item_guid, parts=())
        _, count, pos = header
        if count > 256:
            return None
        parts: List[WorkshopPartSummary] = []
        for _ in range(count):
            part_type_id, pos = read_object_header(data, pos)
            if part_type_id != 504:
                return None
            part_guid, pos = read_guid(data, pos, marker=False)
            _require_bytes(data, pos, 8, "workshop part state")
            condition = f32(data, pos)
            duration_or_count = i32(data, pos + 4)
            pos += 8
            (silver_raw, gold_raw), pos = _read_money_pair_object(data, pos)
            _require_bytes(data, pos, 1, "workshop part status")
            status = data[pos]
            pos += 1
            subpart_count = 0
            sub_header = read_typed_list_header(data, pos)
            if sub_header is None:
                if pos < len(data) and data[pos] == 0xFF:
                    pos += 1
                else:
                    return None
            else:
                _, subpart_count, pos = sub_header
                if subpart_count > 512:
                    return None
                for _ in range(subpart_count):
                    subpart_type_id, pos = read_object_header(data, pos)
                    if subpart_type_id != 507:
                        return None
                    _, pos = _read_nullable_short_string_strict(data, pos)
                    _, pos = _read_money_pair_object(data, pos)
                    _, pos = _read_money_pair_object(data, pos)
                    _require_bytes(data, pos, 4, "workshop subpart tail")
                    pos += 4
            parts.append(
                WorkshopPartSummary(
                    part_guid=part_guid,
                    condition=condition,
                    duration_or_count=duration_or_count,
                    silver_raw=silver_raw,
                    gold_raw=gold_raw,
                    status=status,
                    subpart_count=subpart_count,
                )
            )
        return WorkshopDiagnosisSummary(item_guid=item_guid, parts=tuple(parts))
    except (ValueError, IndexError, struct.error):
        return None


def parse_admin_status(data: bytes) -> Optional[Tuple[Optional[str], float]]:
    try:
        object_type_id, pos = read_object_header(data, 0)
        if object_type_id != 304:
            return None
        text, pos = _read_nullable_short_string_strict(data, pos)
        _require_bytes(data, pos, 4, "admin status value")
        return text, f32(data, pos)
    except (ValueError, IndexError, struct.error):
        return None


def parse_tagged_i64(data: bytes) -> Optional[int]:
    if len(data) < 9 or data[0] != 0x11:
        return None
    return int.from_bytes(data[1:9], "little", signed=True)


def parse_item_scope_summary(data: bytes) -> Optional[Tuple[int, int, int]]:
    try:
        object_type_id, pos = read_object_header(data, 0)
        if object_type_id != 133:
            return None
        _require_bytes(data, pos, 12, "item scope summary")
        return i32(data, pos), i32(data, pos + 4), i32(data, pos + 8)
    except (ValueError, IndexError):
        return None


def parse_shop_result_text(data: bytes) -> Optional[str]:
    try:
        object_type_id, pos = read_object_header(data, 0)
        if object_type_id != 804:
            return None
        value, _ = _read_nullable_short_string_strict(data, pos)
        return value
    except (ValueError, IndexError):
        return None


def parse_fishing_end_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[FishingEndRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.fishing_main_cmd or envelope.sub_cmd != profile.fishing_end_sub_cmd:
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
    return FishingEndRequest(
        call_id=envelope.call_id,
        fishing_gear_id=fishing_gear_id,
        fish_setup_id=fish_setup_id,
    )


def parse_slot_items_response_payload(data: bytes) -> Tuple[SlotItemSummary, ...]:
    def parse_one(pos: int, end: int) -> tuple[Optional[SlotItemSummary], int]:
        try:
            object_type_id, pos = read_object_header(data, pos)
        except (ValueError, IndexError):
            return None, end
        if object_type_id != 136 or pos + 18 > end:
            return None, end
        slot_type = u16(data, pos)
        pos += 2
        item_guid = guid_le(data[pos:pos + 16])
        pos += 16
        return SlotItemSummary(slot_type=slot_type, item_guid=item_guid), pos

    end = len(data)
    header = read_typed_list_header(data, 0)
    if header is None:
        item, _ = parse_one(0, end)
        return (item,) if item is not None else ()
    type_code, count, pos = header
    if type_code != "65":
        return ()
    out: List[SlotItemSummary] = []
    for _ in range(count):
        item, pos = parse_one(pos, end)
        if item is None:
            break
        out.append(item)
    return tuple(out)


def _scan_object_offsets(data: bytes) -> List[Tuple[int, int]]:
    offsets: List[Tuple[int, int]] = []
    pos = 0
    while pos + 5 <= len(data):
        pos = data.find(b"\x01", pos)
        if pos < 0 or pos + 5 > len(data):
            break
        object_type_id = u32(data, pos + 1)
        if 100 <= object_type_id <= 10000:
            offsets.append((pos, object_type_id))
            pos += 5
        else:
            pos += 1
    return offsets


def _plausible_item_float(value: Optional[float]) -> bool:
    if value is None or not math.isfinite(value) or not (-10.0 <= value <= 100.0):
        return False
    if 0.0 < abs(value) < 0.00001:
        return False
    return True


def _parse_rig_definition_at(data: bytes, offset: int, end: int) -> Optional[RigDefinitionSummary]:
    try:
        object_type_id, pos = read_object_header(data, offset)
        if object_type_id != 153:
            return None
        rig_key, pos = read_short_string(data, pos)
        if not rig_key or not rig_key.startswith("rig_"):
            return None
        rig_line_type = data[pos] if pos < end else None
        if pos < end:
            pos += 1
        header = read_typed_list_header(data, pos)
        if header is None:
            return RigDefinitionSummary(rig_key=rig_key, line_type=rig_line_type, components=())
        _, count, pos = header
        components: List[RigComponentSummary] = []
        for _ in range(count):
            if pos + 26 > end:
                break
            component_type, pos = read_object_header(data, pos)
            if component_type != 152:
                break
            line_type = data[pos] if pos < end else None
            pos += 1
            component_guid = None
            if pos + 16 <= end:
                component_guid = guid_le(data[pos:pos + 16])
                pos += 16
            item_id = None
            if pos + 4 <= end:
                item_id = i32(data, pos)
                pos += 4
            components.append(
                RigComponentSummary(
                    line_type=line_type,
                    component_guid=component_guid,
                    item_id=item_id if item_id is not None and item_id > 0 else None,
                )
            )
        return RigDefinitionSummary(
            rig_key=rig_key,
            line_type=rig_line_type,
            components=tuple(components),
        )
    except (ValueError, IndexError, struct.error):
        return None


def _find_item_object_layout(data: bytes, pos: int, end: int) -> Optional[Tuple[int, int, int, int]]:
    best: Optional[Tuple[int, int, int, int, int]] = None
    for gear_start in range(pos + 1, max(pos + 1, end - 45)):
        after_guid = gear_start + 16
        if after_guid + 30 > end:
            continue
        for item_id_shift in (1, 2):
            item_id_pos = after_guid + item_id_shift
            if item_id_pos + 12 > end:
                continue
            item_id = i32(data, item_id_pos)
            durability = f32(data, item_id_pos + 4)
            condition = f32(data, item_id_pos + 8)
            if not (0 < item_id < 300000):
                continue
            if not (_plausible_item_float(durability) and _plausible_item_float(condition)):
                continue
            score = 0
            if gear_start - 1 >= pos and data[gear_start - 1] in (0, 1, 0x8A):
                score += 2
            if gear_start - pos in (17, 21):
                score += 2
            if item_id_shift == 1:
                score += 1
            if best is None or score > best[0]:
                best = (score, gear_start, after_guid, item_id_shift, item_id_pos)
    if best is None:
        return None
    _, gear_start, after_guid, item_id_shift, item_id_pos = best
    return gear_start, after_guid, item_id_shift, item_id_pos


def _parse_item_object_at(
    data: bytes,
    pos: int,
    end: int,
    object_type_id: int,
) -> Optional[ItemObjectSummary]:
    layout = _find_item_object_layout(data, pos, end)
    if layout is None:
        return None
    gear_start, after_guid, item_id_shift, item_id_pos = layout
    item_guid = None
    pre_parent_len = gear_start - pos
    if pre_parent_len in (17, 21) and pos + 16 <= gear_start:
        item_guid = guid_le(data[pos:pos + 16])
    elif pre_parent_len > 17:
        item_guid_pos = gear_start - 17
        if item_guid_pos >= pos and item_guid_pos + 16 <= gear_start:
            item_guid = guid_le(data[item_guid_pos:item_guid_pos + 16])
    parent_guid = guid_le(data[gear_start:after_guid]) if after_guid <= end else None
    slot = data[after_guid] if after_guid < end else None
    item_id = i32(data, item_id_pos) if item_id_pos + 4 <= end else None
    durability = f32(data, item_id_pos + 4) if item_id_pos + 8 <= end else None
    condition = f32(data, item_id_pos + 8) if item_id_pos + 12 <= end else None
    if item_id is None or item_id <= 0:
        return None
    if item_id_shift not in (1, 2):
        return None
    return ItemObjectSummary(
        object_type_id=object_type_id,
        item_guid=item_guid,
        parent_guid=parent_guid,
        slot=slot,
        item_id=item_id,
        durability=durability if _plausible_item_float(durability) else None,
        condition=condition if _plausible_item_float(condition) else None,
    )


def parse_item_state_summary(
    data: bytes,
    *,
    max_items: Optional[int] = 16,
) -> ItemStateSummary:
    object_offsets = _scan_object_offsets(data)
    rigs: List[RigDefinitionSummary] = []
    items: List[ItemObjectSummary] = []
    for index, (offset, object_type_id) in enumerate(object_offsets):
        next_offset = object_offsets[index + 1][0] if index + 1 < len(object_offsets) else len(data)
        if object_type_id == 153:
            rig_end = len(data)
            for later_offset, later_type_id in object_offsets[index + 1:]:
                if later_type_id != 152:
                    rig_end = later_offset
                    break
            rig = _parse_rig_definition_at(data, offset, rig_end)
            if rig is not None and rig not in rigs:
                rigs.append(rig)
            continue
        if 100 <= object_type_id < 200 and object_type_id not in {141, 143, 152, 153}:
            item = _parse_item_object_at(data, offset + 5, next_offset, object_type_id)
            if item is not None and item not in items:
                items.append(item)
    visible_items = items if max_items is None else items[:max_items]
    return ItemStateSummary(
        rig_definitions=tuple(rigs[:8]),
        item_objects=tuple(visible_items),
    )


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
    extra_floats: Tuple[float, ...] = ()
    flag_byte: Optional[bool] = None
    value_raw: Optional[float] = None


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


@dataclass(frozen=True)
class FishingEndRequest:
    call_id: int
    fishing_gear_id: Optional[str]
    fish_setup_id: Optional[str]


@dataclass(frozen=True)
class RepairSelectionSummary:
    component_type: int
    component_key: Optional[str]


@dataclass(frozen=True)
class RepairRequestSummary:
    item_guid: str
    selections: Tuple[RepairSelectionSummary, ...]
    option_enabled: bool
    quoted_cost_raw: int


@dataclass(frozen=True)
class PhoenixArgument:
    marker: int
    kind: str
    value: object


@dataclass(frozen=True)
class BuildingRpcRequest:
    call_id: int
    main_cmd: int
    sub_cmd: int
    arguments: Tuple[PhoenixArgument, ...]
    payload: bytes
    created_at: float


@dataclass(frozen=True)
class ObservedCatchRecord:
    record_guid: str
    fish_key: str
    weight_raw: int
    size_enum: Optional[int]


@dataclass(frozen=True)
class FishSaleResult:
    fish_guid: str
    paid_raw: int
    status: int


@dataclass(frozen=True)
class WorkshopPartSummary:
    part_guid: str
    condition: float
    duration_or_count: int
    silver_raw: int
    gold_raw: int
    status: int
    subpart_count: int


@dataclass(frozen=True)
class WorkshopDiagnosisSummary:
    item_guid: str
    parts: Tuple[WorkshopPartSummary, ...]


@dataclass(frozen=True)
class RigComponentSummary:
    line_type: Optional[int]
    component_guid: Optional[str]
    item_id: Optional[int]


@dataclass(frozen=True)
class RigDefinitionSummary:
    rig_key: str
    line_type: Optional[int]
    components: Tuple[RigComponentSummary, ...]


@dataclass(frozen=True)
class ItemObjectSummary:
    object_type_id: int
    item_guid: Optional[str]
    parent_guid: Optional[str]
    slot: Optional[int]
    item_id: Optional[int]
    durability: Optional[float]
    condition: Optional[float]


@dataclass(frozen=True)
class ItemStateSummary:
    rig_definitions: Tuple[RigDefinitionSummary, ...]
    item_objects: Tuple[ItemObjectSummary, ...]


@dataclass(frozen=True)
class SlotItemSummary:
    slot_type: int
    item_guid: str


@dataclass(frozen=True)
class ItemCatalogEntry:
    catalog_id: str
    category: str
    category_label: str
    name: str
    stats: Dict[str, object]


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

    def clone(self) -> "RC4Stream":
        clone = object.__new__(RC4Stream)
        clone._s = self._s.copy()
        clone._i = self._i
        clone._j = self._j
        return clone


def try_parse_auth_packet(data: bytes) -> Optional[Tuple[str, int]]:
    # 打开钓鱼站等场景下游戏重连 realtime 时，auth 包开头可能是 \x01\x00 或 \x01\x01，
    # 后续 token 结构完全相同，都需要识别。
    if len(data) < 6:
        return None
    if data[:2] not in (b"\x01\x00", b"\x01\x01"):
        return None
    token_len = u32(data, 2)
    total = 6 + token_len
    if token_len <= 0 or len(data) < total:
        return None
    token = data[6:total].decode("utf-8", errors="strict")
    if token.count("|") < 3:
        return None
    return token, total


def is_complete_but_invalid_auth_packet(data: bytes) -> bool:
    """判断缓冲是否已凑齐"完整认证包长度"但解析失败（确定不是 RF4 认证连接）。

    认证包格式：2 字节头(\x01\x00/\x01\x01) + u32 长度 + token。
    只要长度字段给出总长且已收满，却仍解析失败，说明这不是 RF4 realtime 认证，
    无需等待 1MB 超时即可进入透传。
    """
    if len(data) < 6:
        return False
    if data[:2] not in (b"\x01\x00", b"\x01\x01"):
        return False
    token_len = u32(data, 2)
    if token_len <= 0 or token_len > (1 << 16):
        # 长度非法（过大/过小）同样不可能成为认证包，立即判死。
        return True
    if len(data) < 6 + token_len:
        return False
    return try_parse_auth_packet(data) is None


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
            pos += 4
        # 鱼设置类 gkfghccolil 的精确网络布局（dump.cs + GameAssembly.dll 反汇编
        # cmjcbaheigb）：0x2C float 长度 / 0x30 int 重量 / 之后
        # 0x34 float, 0x38 float, 0x3C bool, 0x40..0x70 float×13。
        # 0x78 起为 jiefmbnjlcp[] 数组等复合字段，不在此解析。
        extra_floats_before: List[float] = []
        flag_byte: Optional[bool] = None
        extra_floats_after: List[float] = []
        for _ in range(2):
            if pos + 4 <= len(envelope.payload):
                extra_floats_before.append(struct.unpack_from("<f", envelope.payload, pos)[0])
                pos += 4
        if pos < len(envelope.payload):
            flag_byte = envelope.payload[pos] != 0
            pos += 1
        for _ in range(13):
            if pos + 4 <= len(envelope.payload):
                extra_floats_after.append(struct.unpack_from("<f", envelope.payload, pos)[0])
                pos += 4
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
        extra_floats=tuple(extra_floats_before + extra_floats_after),
        flag_byte=flag_byte,
        value_raw=extra_floats_before[0] if extra_floats_before else None,
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


@dataclass(frozen=True)
class FightPullRequest:
    call_id: int
    fishing_gear_id: Optional[str]
    tick: Optional[int]


def parse_fight_pull_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[FightPullRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.fishing_main_cmd or envelope.sub_cmd != profile.fight_pull_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        fishing_gear_id = None
        if pos < len(envelope.payload) and envelope.payload[pos] == 0x0C:
            fishing_gear_id, pos = read_guid(envelope.payload, pos, marker=True)
        tick = None
        if pos + 5 <= len(envelope.payload) and envelope.payload[pos] == 0x10:
            tick = u32(envelope.payload, pos + 1)
    except (ValueError, IndexError):
        return None
    if not fishing_gear_id:
        return None
    return FightPullRequest(
        call_id=envelope.call_id,
        fishing_gear_id=fishing_gear_id,
        tick=tick,
    )


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

    weight_raw = None
    size_enum = None

    # 在鱼名之后的一段区域内，找一个合理的 u32 作为重量(克)。
    # 服务器响应里鱼名与重量之间可能有其他字段，按 4 字节对齐逐个试探。
    start = idx + len(needle)
    end = min(len(plain_body), start + 64)
    for offset in range(0, 32, 4):
        pos = start + offset
        if pos + 4 > end:
            break
        candidate = u32(plain_body, pos)
        if 10 < candidate < 10000000:
            weight_raw = candidate
            if pos + 10 <= len(plain_body):
                size_candidate = u16(plain_body, pos + 8)
                if 0 < size_candidate < 256:
                    size_enum = size_candidate
            break

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

