from __future__ import annotations

import base64
import binascii
import bisect
import gzip
import hashlib
import json
import os
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional


RF4_GAME_CATALOG_BUILD = "2026.07.11-r12"


FISH_PROTOCOL_ALIASES = {
    "a_sleeper": "a.sleeper",
    "c_bream": "c.bream",
    "c_carp": "c.carp",
    "c_roach": "c.roach",
    "e_chub": "e.chub",
    "e_pikeperch": "e.pikeperch",
    "n_pike": "n.pike",
    "s_bream": "s.bream",
    "s_orfe": "s.orfe",
}

# Old sample rules used live-bait/resource keys or Chinese display text.  They
# are accepted only while importing/editing and are always saved as canonical
# fish protocol keys.
LEGACY_FISH_ALIASES = {
    "c_carp_lf": "c.carp",
    "诸子鲤": "e.chub",
    "诸子鳞": "e.chub",
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


@dataclass(frozen=True)
class GearConfigRecord:
    config_id: int
    system_id: str
    config_type_id: int
    object_type_id: int
    subtype: int
    group_key: str
    attributes: dict


def gear_group_for_config(config_type_id: int, subtype: int) -> Optional[str]:
    if config_type_id == 12046:
        return ROD_SUBTYPES.get(subtype, "rod_other")
    if config_type_id == 12035:
        return REEL_SUBTYPES.get(subtype, "reel_other")
    if config_type_id == 12024:
        return LINE_SUBTYPES.get(subtype, "line_other")
    if config_type_id == 12020:
        return "hook"
    return None


def fish_manifest_ids(labels: Mapping[str, str], extra_ids: Iterable[str] = ()) -> set[str]:
    ids = {str(value) for value in extra_ids if str(value)}
    ids.update(key[5:] for key in labels if key.startswith("card_") and len(key) > 5)
    ids.update(FISH_PROTOCOL_ALIASES)
    return ids


def canonical_fish_key(
    value: object,
    labels: Mapping[str, str],
    fish_ids: Iterable[str],
) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    ids = set(fish_ids)
    canonical_ids = {FISH_PROTOCOL_ALIASES.get(fish_id, fish_id) for fish_id in ids}
    direct = FISH_PROTOCOL_ALIASES.get(text, LEGACY_FISH_ALIASES.get(text, text))
    if direct in canonical_ids:
        return direct

    # Reverse lookup is deliberately restricted to the fish manifest.  The
    # global localization table also contains bait called "帝王蟹" etc.
    for fish_id in ids:
        protocol_id = FISH_PROTOCOL_ALIASES.get(fish_id, fish_id)
        if text in {
            str(labels.get(protocol_id) or "").strip(),
            str(labels.get(fish_id) or "").strip(),
        }:
            return protocol_id
    return None


def _short_ascii_strings(data: bytes):
    pos = 0
    end = len(data)
    while pos < end:
        size = data[pos]
        if 3 <= size <= 120 and pos + 1 + size <= end:
            raw = data[pos + 1:pos + 1 + size]
            if re.fullmatch(rb"[A-Za-z0-9_.\-]+", raw):
                try:
                    yield pos, raw.decode("ascii")
                except UnicodeDecodeError:
                    pass
        pos += 1


def _read_short_ascii(data: bytes, pos: int) -> Optional[tuple[str, int]]:
    if pos >= len(data):
        return None
    size = data[pos]
    if size == 0xFF or pos + 1 + size > len(data):
        return None
    raw = data[pos + 1:pos + 1 + size]
    try:
        return raw.decode("ascii"), pos + 1 + size
    except UnicodeDecodeError:
        return None


def _parse_enum_array(data: bytes, pos: int) -> Optional[tuple[tuple[int, ...], int]]:
    if pos >= len(data) or data[pos] != 0x07:
        return None
    parsed_type = _read_short_ascii(data, pos + 1)
    if parsed_type is None:
        return None
    _type_name, cursor = parsed_type
    if cursor + 2 > len(data):
        return None
    count = int.from_bytes(data[cursor:cursor + 2], "little", signed=False)
    cursor += 2
    end = cursor + count * 4
    if count > 128 or end > len(data):
        return None
    values = tuple(
        int.from_bytes(data[index:index + 4], "little", signed=True)
        for index in range(cursor, end, 4)
    )
    return values, end


def _parse_string_array_end(data: bytes, pos: int) -> Optional[int]:
    if pos >= len(data) or data[pos] != 0x04 or pos + 3 > len(data):
        return None
    count = int.from_bytes(data[pos + 1:pos + 3], "little", signed=False)
    if count > 1024:
        return None
    cursor = pos + 3
    for _ in range(count):
        if cursor + 4 > len(data):
            return None
        size = int.from_bytes(data[cursor:cursor + 4], "little", signed=False)
        cursor += 4
        if size == 0x7FFFFFFF:
            continue
        cursor += size
        if cursor > len(data):
            return None
    return cursor


def _rod_allowed_reel_sizes(data: bytes, start: int, item_id_pos: int) -> tuple[int, ...]:
    """Read rod config's enum[] immediately before its trailing string[]."""

    kind_pos = item_id_pos - 1
    search_end = max(start, kind_pos)
    for enum_pos in range(start, search_end):
        parsed = _parse_enum_array(data, enum_pos)
        if parsed is None:
            continue
        values, string_array_pos = parsed
        string_end = _parse_string_array_end(data, string_array_pos)
        if string_end == kind_pos:
            return tuple(sorted({value for value in values if value > 0}))
    return ()


def gear_configs_compatible(source: Mapping, target: Mapping) -> bool:
    if str(source.get("group_key") or "") != str(target.get("group_key") or ""):
        return False
    if int(source.get("object_type_id", 0)) != int(target.get("object_type_id", 0)):
        return False
    if int(source.get("subtype", -1)) != int(target.get("subtype", -2)):
        return False

    source_attributes = source.get("attributes") or {}
    target_attributes = target.get("attributes") or {}
    if isinstance(source_attributes, str):
        try:
            source_attributes = json.loads(source_attributes)
        except json.JSONDecodeError:
            source_attributes = {}
    if isinstance(target_attributes, str):
        try:
            target_attributes = json.loads(target_attributes)
        except json.JSONDecodeError:
            target_attributes = {}

    object_type_id = int(source.get("object_type_id", 0))
    if object_type_id == 149:
        source_size = int(source_attributes.get("reel_size", 0) or 0)
        target_size = int(target_attributes.get("reel_size", 0) or 0)
        return source_size > 0 and source_size == target_size
    if object_type_id == 157:
        source_sizes = {int(value) for value in source_attributes.get("allowed_reel_sizes", [])}
        target_sizes = {int(value) for value in target_attributes.get("allowed_reel_sizes", [])}
        # A replacement rod is safe for every reel accepted by the source rod
        # only when the target keeps at least that complete size set.
        return source_sizes.issubset(target_sizes)
    return True


def extract_gear_config_records(
    package: bytes,
    known_system_ids: Optional[set[str]] = None,
) -> list[GearConfigRecord]:
    """Extract authoritative configId/systemId pairs from game/configs type 1.

    Each relevant DTO ends with the shared jjpjbijlcgl base fields:
    one-byte config kind, int32 config id, then a one-byte-length systemId.
    The derived DTO starts with tag 01 + its uint32 type id and a one-byte
    subtype.  This lets us extract the required mapping without guessing a
    number embedded in systemId and without vendoring the full DTO registry.
    """

    headers: list[tuple[int, int, int, int]] = []
    for config_type_id, (object_type_id, _base_group) in CONFIG_TYPE_INFO.items():
        needle = b"\x01" + config_type_id.to_bytes(4, "little")
        start = 0
        while True:
            offset = package.find(needle, start)
            if offset < 0:
                break
            if offset + 5 < len(package):
                headers.append((offset, config_type_id, object_type_id, package[offset + 5]))
            start = offset + 1
    headers.sort()
    header_offsets = [entry[0] for entry in headers]
    if not headers:
        return []

    candidates: dict[int, list[tuple[int, int, str]]] = {}
    for length_pos, system_id in _short_ascii_strings(package):
        if known_system_ids is not None and system_id not in known_system_ids:
            continue
        if length_pos < 5:
            continue
        if package[length_pos - 5] > 32:
            continue
        config_id = int.from_bytes(package[length_pos - 4:length_pos], "little", signed=True)
        if not 0 < config_id < 1_000_000:
            continue
        header_index = bisect.bisect_right(header_offsets, length_pos) - 1
        if header_index < 0:
            continue
        header_offset, config_type_id, object_type_id, subtype = headers[header_index]
        # A genuine item DTO is compact.  This also prevents an unrelated
        # string much later in the package inheriting the last item header.
        if length_pos - header_offset > 16_384:
            continue
        candidates.setdefault(header_index, []).append((length_pos, config_id, system_id))

    found: dict[tuple[int, str], GearConfigRecord] = {}
    for header_index, values in candidates.items():
        # Derived fields (including referenced component DTOs) are serialized
        # before the shared base.  The main item's systemId is therefore the
        # last valid localized base string before the next top-level item DTO.
        length_pos, config_id, system_id = max(values)
        header_offset, config_type_id, object_type_id, subtype = headers[header_index]
        group_key = gear_group_for_config(config_type_id, subtype)
        if not group_key:
            continue
        attributes: dict = {}
        if object_type_id == 149 and header_offset + 6 < len(package):
            reel_size = int(package[header_offset + 6])
            if 0 < reel_size <= 64:
                attributes["reel_size"] = reel_size
        elif object_type_id == 157:
            allowed_sizes = _rod_allowed_reel_sizes(
                package,
                header_offset + 6,
                length_pos - 4,
            )
            attributes["allowed_reel_sizes"] = list(allowed_sizes)
        record = GearConfigRecord(
            config_id=config_id,
            system_id=system_id,
            config_type_id=config_type_id,
            object_type_id=object_type_id,
            subtype=subtype,
            group_key=group_key,
            attributes=attributes,
        )
        found[(config_id, system_id)] = record
    return sorted(found.values(), key=lambda record: (record.group_key, record.system_id))


def decode_config_response_text(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def decode_config_response_payload(payload: bytes) -> bytes:
    """Decode the single Phoenix value returned by game/configs 1/4.

    Current clients return a base64 string.  Byte-array responses are also
    accepted because older Phoenix serializers expose the same payload using
    tag 0x08.
    """

    if not payload:
        raise ValueError("empty game/configs response")
    tag = payload[0]
    if tag == 0x08:
        if len(payload) < 5:
            raise ValueError("truncated game/configs byte array")
        size = int.from_bytes(payload[1:5], "little", signed=False)
        end = 5 + size
        if end > len(payload):
            raise ValueError("truncated game/configs byte array body")
        return payload[5:end]

    widths = {0x14: 1, 0x15: 2, 0x16: 4}
    width = widths.get(tag)
    if width is None or len(payload) < 1 + width:
        raise ValueError(f"unsupported game/configs Phoenix tag 0x{tag:02x}")
    size = int.from_bytes(payload[1:1 + width], "little", signed=False)
    null_size = {1: 0xFF, 2: 0xFFFF, 4: 0x7FFFFFFF}[width]
    if size == null_size:
        raise ValueError("null game/configs response")
    start = 1 + width
    end = start + size
    if end > len(payload):
        raise ValueError("truncated game/configs base64 string")
    try:
        value = payload[start:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("game/configs response is not ASCII base64") from exc
    return decode_config_response_text(value)


def decode_config_version_hashes(payload: bytes) -> list[str]:
    """Decode the string[] returned by the client's natural game/configs 1/5 call."""

    if len(payload) < 3 or payload[0] != 0x04:
        raise ValueError("game/configs_version response is not a string array")
    count = int.from_bytes(payload[1:3], "little", signed=False)
    if count <= 0 or count > 64:
        raise ValueError("invalid game/configs_version hash count")
    pos = 3
    values: list[str] = []
    for _ in range(count):
        if pos + 4 > len(payload):
            raise ValueError("truncated game/configs_version string length")
        size = int.from_bytes(payload[pos:pos + 4], "little", signed=False)
        pos += 4
        if size > 256 or pos + size > len(payload):
            raise ValueError("truncated game/configs_version string")
        try:
            value = payload[pos:pos + size].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII game/configs_version hash") from exc
        pos += size
        if not re.fullmatch(r"[0-9a-fA-F]{40}", value):
            raise ValueError("invalid game/configs_version hash")
        values.append(value.lower())
    return values


RF4_PRODUCT_DIR_NAMES = (
    "RussianFishing4CN",
    "RussianFishing4",
    "Russian Fishing 4",
    "RussianFishing4EN",
    "RussianFishing4DE",
    "RussianFishing4ES",
    "RussianFishing4KR",
    "RussianFishing4JP",
    "RussianFishing4IT",
    "RussianFishing4ID",
    "RussianFishing4Steam",
    "RussianFishing4VK",
)

RF4_VENDOR_DIR_NAMES = (
    "RussianFishingLLC",
    "Russian Fishing LLC",
)


def _int32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _dotnet_two_lane_char_hash(value: str, seed: int) -> int:
    """Return the two-lane DJB hash used by several Mono/.NET string builds."""

    hash1 = _int32(seed)
    hash2 = _int32(seed)
    for index in range(0, len(value), 2):
        first = ord(value[index])
        if first == 0:
            break
        hash1 = _int32(_int32(hash1 * 33) ^ first)
        if index + 1 >= len(value):
            break
        second = ord(value[index + 1])
        if second == 0:
            break
        hash2 = _int32(_int32(hash2 * 33) ^ second)
    return _int32(hash1 + _int32(hash2 * 1566083941))


def _dotnet_framework_dword_hash(value: str) -> int:
    """Reference-source 64-bit String.GetHashCode over packed UTF-16 dwords."""

    raw = value.encode("utf-16le") + b"\x00" * 8
    hash1 = _int32(0x15051505)
    hash2 = hash1
    remaining = len(value)
    pos = 0

    def mix(current: int, word: int) -> int:
        rotated = _int32(_int32(current * 33) + (_int32(current) >> 27))
        return _int32(rotated ^ word)

    while remaining > 2:
        first = int.from_bytes(raw[pos:pos + 4], "little", signed=True)
        second = int.from_bytes(raw[pos + 4:pos + 8], "little", signed=True)
        hash1 = mix(hash1, first)
        hash2 = mix(hash2, second)
        pos += 8
        remaining -= 4
    if remaining > 0:
        first = int.from_bytes(raw[pos:pos + 4], "little", signed=True)
        hash1 = mix(hash1, first)
    return _int32(hash1 + _int32(hash2 * 1566083941))


def _mono_string_hash31(value: str) -> int:
    result = 0
    for character in value:
        result = _int32(_int32(result * 31) + ord(character))
    return result


def _config_cache_seed_candidates(value: str) -> list[tuple[str, int]]:
    """Deterministic String.GetHashCode variants shipped across Unity runtimes."""

    raw = (
        ("dotnet-packed-char", _dotnet_two_lane_char_hash(value, 0x15051505)),
        ("dotnet-plain-char", _dotnet_two_lane_char_hash(value, 5381)),
        ("dotnet-packed-dword", _dotnet_framework_dword_hash(value)),
        ("mono-31", _mono_string_hash31(value)),
    )
    result: list[tuple[str, int]] = []
    seen: set[int] = set()
    for name, seed in raw:
        if seed in seen:
            continue
        seen.add(seed)
        result.append((name, seed))
    return result


class _DotNetRandom:
    """The subtractive System.Random implementation shipped with this client."""

    _MBIG = 2147483647
    _MSEED = 161803398

    def __init__(self, seed: int):
        subtraction = self._MBIG if seed == -2147483648 else abs(int(seed))
        mj = self._MSEED - subtraction
        if mj < 0:
            mj += self._MBIG
        self._seed_array = [0] * 56
        self._seed_array[55] = mj
        mk = 1
        for index in range(1, 55):
            ii = (21 * index) % 55
            self._seed_array[ii] = mk
            mk = mj - mk
            if mk < 0:
                mk += self._MBIG
            mj = self._seed_array[ii]
        for _ in range(4):
            for index in range(1, 56):
                self._seed_array[index] -= self._seed_array[1 + (index + 30) % 55]
                if self._seed_array[index] < 0:
                    self._seed_array[index] += self._MBIG
        self._inext = 0
        self._inextp = 21

    def _internal_sample(self) -> int:
        self._inext += 1
        if self._inext >= 56:
            self._inext = 1
        self._inextp += 1
        if self._inextp >= 56:
            self._inextp = 1
        value = self._seed_array[self._inext] - self._seed_array[self._inextp]
        if value == self._MBIG:
            value -= 1
        if value < 0:
            value += self._MBIG
        self._seed_array[self._inext] = value
        return value

    def next(self, max_value: int) -> int:
        if max_value < 0:
            raise ValueError("max_value must be non-negative")
        return int((self._internal_sample() * (1.0 / self._MBIG)) * max_value)


def _transform_config_cache(data: bytes, seed: int, *, reverse: bool) -> bytes:
    """Apply one native byte-swap pass using an already resolved hash seed."""

    if not data:
        return b""

    result = bytearray(data)
    random = _DotNetRandom(seed)
    table = [random.next(256) for _ in range(256)]
    # Native mfnebeibkah.hokjdangdhb.ibfnmiadikg returns EAX after idiv, i.e.
    # the quotient Random.Next(data.Length) / table.Length (integer division).
    offsets = [random.next(len(result)) // len(table) for _ in range(256)]
    indices = range(len(result) - 1, -1, -1) if reverse else range(len(result))
    for index in indices:
        page, column = divmod(index, len(table))
        swap_index = (offsets[page % len(offsets)] + table[column]) % len(result)
        if swap_index != index:
            result[index], result[swap_index] = result[swap_index], result[index]
    return bytes(result)


def iter_decrypt_config_cache_variants(
    data: bytes,
    cache_hash: str,
) -> Iterable[tuple[str, bytes]]:
    """Yield native-runtime candidates; the server SHA1 selects the exact one."""

    normalized_hash = str(cache_hash or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", normalized_hash):
        raise ValueError("invalid config cache hash")
    for seed_name, seed in _config_cache_seed_candidates(normalized_hash):
        yield f"{seed_name}/reverse", _transform_config_cache(data, seed, reverse=True)
        yield f"{seed_name}/forward", _transform_config_cache(data, seed, reverse=False)


def decrypt_config_cache(data: bytes, cache_hash: str) -> bytes:
    """Backward-compatible primary candidate; callers should verify its SHA1."""

    return next(iter_decrypt_config_cache_variants(data, cache_hash))[1]


def _unique_paths(values: Iterable[Path]) -> list[Path]:
    unique: list[Path] = []
    seen = set()
    for value in values:
        path = Path(value)
        key = os.path.normcase(os.path.normpath(str(path)))
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _other_windows_user_platform_roots() -> list[Path]:
    """Return exact AppData roots for sibling profiles, without recursive crawling."""

    raw_profile = str(os.environ.get("USERPROFILE") or "").strip()
    user_roots: list[Path] = []
    if raw_profile:
        current_profile = Path(os.path.expandvars(raw_profile)).expanduser()
        user_roots.append(current_profile.parent)
    system_drive = str(os.environ.get("SystemDrive") or "").strip()
    if system_drive:
        user_roots.append(Path(system_drive + os.sep) / "Users")
    public_profile = str(os.environ.get("PUBLIC") or "").strip()
    if public_profile:
        user_roots.append(Path(public_profile).parent)
    if not user_roots:
        return []
    profiles: list[Path] = []
    for users_root in _unique_paths(user_roots):
        try:
            profiles.extend(value for value in users_root.iterdir() if value.is_dir())
        except OSError:
            continue
    profiles = sorted(
        _unique_paths(profiles),
        key=lambda value: value.name.casefold(),
    )[:64]
    roots: list[Path] = []
    for profile in profiles:
        roots.extend(
            (
                profile / "AppData" / "Roaming",
                profile / "AppData" / "LocalLow",
                profile / "AppData" / "Local",
            )
        )
    return roots


def local_config_cache_search_roots(extra_roots: Iterable[Path] = ()) -> list[Path]:
    """Return bounded RF4 vendor roots searched for configType=1 caches."""

    home = Path.home()
    app_data = str(os.environ.get("APPDATA") or "").strip()
    platform_roots = [
        Path(app_data) if app_data else home / "AppData" / "Roaming",
        home / "AppData" / "LocalLow",
        home / "Library" / "Application Support",
        home / ".config" / "unity3d",
    ]
    local_app_data = str(os.environ.get("LOCALAPPDATA") or "").strip()
    if local_app_data:
        local_path = Path(local_app_data)
        platform_roots.extend(
            [
                local_path.parent / "LocalLow",
                local_path,
            ]
        )
    platform_roots.extend(_other_windows_user_platform_roots())
    roots = [
        platform_root / vendor
        for platform_root in platform_roots
        for vendor in RF4_VENDOR_DIR_NAMES
    ]
    roots.extend(Path(value) for value in extra_roots)
    return _unique_paths(roots)


def _explicit_cache_paths(value: object) -> tuple[list[Path], list[Path]]:
    raw = str(value or "").strip().strip('"')
    if not raw:
        return [], []
    path = Path(os.path.expandvars(raw)).expanduser()
    if path.suffix.lower() == ".dat":
        return [path], []
    file_names = ("c0001.dat", "c1.dat", "1.dat")
    cache_dirs = ("Temp", "temp", "cache", "Cache", "uwcache")
    paths = [path / name for name in file_names]
    if path.name.lower() not in {name.lower() for name in cache_dirs}:
        for cache_dir in cache_dirs:
            paths.extend(path / cache_dir / name for name in file_names)
    return paths, [path]


def preferred_local_config_cache_path(configured_path: object = "") -> Path:
    """Return the concrete path shown in diagnostics before a cache is found."""

    explicit, _roots = _explicit_cache_paths(configured_path)
    if explicit:
        return explicit[0]
    override, _roots = _explicit_cache_paths(os.environ.get("RF4_CONFIG_CACHE"))
    if override:
        return override[0]
    app_data = str(os.environ.get("APPDATA") or "").strip()
    base = Path(app_data) if app_data else Path.home() / "AppData" / "Roaming"
    return base / "RussianFishingLLC" / "RussianFishing4CN" / "Temp" / "c0001.dat"


def local_config_cache_candidates(
    extra_roots: Iterable[Path] = (),
    configured_path: object = "",
) -> list[Path]:
    """Return existing configType=1 caches from exact, bounded RF4 locations."""

    configured_paths, configured_roots = _explicit_cache_paths(configured_path)
    override_paths, override_roots = _explicit_cache_paths(os.environ.get("RF4_CONFIG_CACHE"))
    paths = list(configured_paths) + list(override_paths)
    roots = local_config_cache_search_roots(
        [*configured_roots, *override_roots, *(Path(value) for value in extra_roots)]
    )

    file_names = ("c0001.dat", "c1.dat", "1.dat")
    cache_dirs = ("Temp", "temp", "cache", "Cache", "uwcache")
    for root in roots:
        # Keep the native vendor directory itself as a fallback and discover
        # direct child product names added by future regional clients.  This
        # is a bounded one-level scan, not a recursive disk crawl.
        for cache_dir in cache_dirs:
            paths.extend(root / cache_dir / name for name in file_names)
        paths.extend(root / name for name in file_names)
        for product in RF4_PRODUCT_DIR_NAMES:
            product_path = root / product
            for cache_dir in cache_dirs:
                paths.extend(product_path / cache_dir / name for name in file_names)
            paths.extend(product_path / name for name in file_names)
        try:
            discovered_products = sorted(
                (value for value in root.iterdir() if value.is_dir()),
                key=lambda value: value.name.casefold(),
            )
        except OSError:
            discovered_products = []
        for product_path in discovered_products:
            for cache_dir in cache_dirs:
                paths.extend(product_path / cache_dir / name for name in file_names)
            paths.extend(product_path / name for name in file_names)

    return [path for path in _unique_paths(paths) if path.is_file()]


def _cache_payload_variants(data: bytes) -> Iterable[bytes]:
    yield data
    if data.startswith(b"\x1f\x8b"):
        try:
            payload = gzip.decompress(data)
            if len(payload) <= 256 * 1024 * 1024:
                yield payload
        except (OSError, EOFError):
            pass
    if len(data) > 2 and data[0] == 0x78:
        try:
            payload = zlib.decompress(data)
            if len(payload) <= 256 * 1024 * 1024:
                yield payload
        except zlib.error:
            pass
    stripped = data.strip()
    compact = re.sub(rb"\s+", b"", stripped)
    if compact and len(compact) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/=]+", compact):
        try:
            yield base64.b64decode(compact, validate=True)
        except (ValueError, binascii.Error):
            pass


def extract_gear_config_records_from_cache(
    path: Path,
    known_system_ids: Optional[set[str]] = None,
    cache_hash: Optional[str] = None,
    diagnostics: Optional[dict[str, object]] = None,
) -> list[GearConfigRecord]:
    if diagnostics is not None:
        diagnostics.clear()
        diagnostics.update(
            {
                "path": str(path),
                "file_size": 0,
                "expected_sha1": str(cache_hash or "").strip().lower(),
                "decrypted_sha1": "",
                "decrypt_variant": "",
                "decrypt_attempts": 0,
                "hash_match": False,
                "raw_head": "",
                "decrypted_head": "",
                "payload_variants": 0,
                "type_header_counts": {},
                "record_count": 0,
                "unfiltered_record_count": 0,
                "error": "",
            }
        )
    try:
        size = path.stat().st_size
        if diagnostics is not None:
            diagnostics["file_size"] = int(size)
        if size <= 0 or size > 256 * 1024 * 1024:
            if diagnostics is not None:
                diagnostics["error"] = "cache file size is outside the supported range"
            return []
        data = path.read_bytes()
        if diagnostics is not None:
            diagnostics["raw_head"] = data[:16].hex()
    except OSError as exc:
        if diagnostics is not None:
            diagnostics["error"] = f"read failed: {exc}"
        return []
    sources = [] if cache_hash else [data]
    if cache_hash:
        try:
            expected_sha1 = str(cache_hash).strip().lower()
            first_result: Optional[tuple[str, bytes, str]] = None
            matched: Optional[tuple[str, bytes, str]] = None
            attempts = 0
            for variant_name, decrypted in iter_decrypt_config_cache_variants(data, cache_hash):
                attempts += 1
                decrypted_sha1 = hashlib.sha1(decrypted).hexdigest()
                candidate = (variant_name, decrypted, decrypted_sha1)
                if first_result is None:
                    first_result = candidate
                if decrypted_sha1 == expected_sha1:
                    matched = candidate
                    break
            selected = matched or first_result
            if diagnostics is not None:
                diagnostics["decrypt_attempts"] = attempts
                if selected is not None:
                    diagnostics["decrypt_variant"] = selected[0]
                    diagnostics["decrypted_sha1"] = selected[2]
                    diagnostics["decrypted_head"] = selected[1][:16].hex()
                diagnostics["hash_match"] = matched is not None
                if matched is None:
                    diagnostics["error"] = "no supported IL2CPP hash/swap variant matched server SHA1"
            if matched is not None:
                sources.append(matched[1])
        except ValueError as exc:
            if diagnostics is not None:
                diagnostics["error"] = f"decrypt failed: {exc}"
    best: list[GearConfigRecord] = []
    variant_count = 0
    best_header_counts: dict[int, int] = {}
    best_unfiltered_count = 0
    for source in sources:
        for payload in _cache_payload_variants(source):
            variant_count += 1
            header_counts = {
                config_type_id: payload.count(
                    b"\x01" + config_type_id.to_bytes(4, "little")
                )
                for config_type_id in CONFIG_TYPE_INFO
            }
            records = extract_gear_config_records(payload, known_system_ids)
            if not records and known_system_ids is not None and any(header_counts.values()):
                best_unfiltered_count = max(
                    best_unfiltered_count,
                    len(extract_gear_config_records(payload, None)),
                )
            if len(records) > len(best):
                best = records
                best_header_counts = header_counts
            elif not best_header_counts and any(header_counts.values()):
                best_header_counts = header_counts
    if diagnostics is not None:
        diagnostics["payload_variants"] = variant_count
        diagnostics["type_header_counts"] = best_header_counts
        diagnostics["record_count"] = len(best)
        diagnostics["unfiltered_record_count"] = best_unfiltered_count
    return best
