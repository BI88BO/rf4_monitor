# --- Fish localization ---
import json
import mmap
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Optional

from . import data_root

PACKAGE_DIR = Path(__file__).resolve().parent
# 打包态(exe)下数据根指向 exe 所在目录，源码运行时指向脚本目录，保证可写数据(exe 旁)可定位。
THIS_DIR = data_root()
REPO_ROOT = THIS_DIR.parents[1]

BASE = THIS_DIR
ROOT = REPO_ROOT
CACHE_DIR = BASE / ".cache"
BUNDLED_LABEL_PATH = BASE / "fish_labels_zh.json"
SYSTEM_LABEL_RE = re.compile(
    r'"systemId":"((?:\\.|[^"\\])*)","name":"((?:\\.|[^"\\])*)","description":'
)
CJK_RE = re.compile(r"[\u3400-\u9fff]")


def _json_unescape(value: str) -> str:
    return json.loads(f'"{value}"')


def _contains_cjk(value: str) -> bool:
    return bool(CJK_RE.search(value))


def extract_system_labels_from_text(text: str) -> Dict[str, str]:
    grouped: Dict[str, list[str]] = {}
    for raw_key, raw_name in SYSTEM_LABEL_RE.findall(text):
        key = _json_unescape(raw_key).strip()
        name = _json_unescape(raw_name).strip()
        if not key or not name:
            continue
        grouped.setdefault(key, []).append(name)

    selected: Dict[str, str] = {}
    for key, values in grouped.items():
        chosen = next((value for value in values if _contains_cjk(value)), None)
        if chosen is None:
            chosen = next((value for value in values if value), None)
        if chosen:
            selected[key] = chosen
    return selected


def _find_locale_blob(resources_assets: Path, locale_id: str) -> str:
    marker = f'"localeId":"{locale_id}"'.encode("utf-8")
    next_marker = b'"localeId":"'
    with resources_assets.open("rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        start = mm.find(marker)
        if start < 0:
            raise FileNotFoundError(f"locale {locale_id!r} was not found in {resources_assets}")
        end = mm.find(next_marker, start + len(marker))
        if end < 0:
            end = len(mm)
        return mm[start:end].decode("utf-8", errors="ignore")


def extract_system_labels_from_resources(resources_assets: Path, locale_id: str = "zh_CN") -> Dict[str, str]:
    return extract_system_labels_from_text(_find_locale_blob(resources_assets, locale_id))


def _iter_fixed_drive_roots() -> list[Path]:
    import string

    roots: list[Path] = []
    for letter in string.ascii_uppercase:
        root = Path(f"{letter}:/")
        try:
            if root.exists():
                roots.append(root)
        except OSError:
            continue
    return roots


def _extra_rf4_data_dirs() -> list[Path]:
    """常见游戏安装布局下的 rf4_x64_Data 目录（官方启动器/Steam 库）。"""
    patterns = (
        ("RF4*", "rf4game", "Game", "rf4_x64_Data"),
        ("RF4*", "Game", "rf4_x64_Data"),
        ("*Steam*", "steamapps", "common", "Russian Fishing 4", "rf4_x64_Data"),
    )
    found: list[Path] = []
    for root in _iter_fixed_drive_roots():
        for pattern in patterns:
            try:
                found.extend(root.glob("/".join(pattern)))
            except OSError:
                continue
    return found


def _candidate_resources_assets(profile_name: str) -> Iterable[Path]:
    candidates: list[Path] = []
    direct = ROOT / "version" / profile_name / "rf4_x64_Data" / "resources.assets"
    if direct.exists():
        candidates.append(direct)
    try:
        for data_dir in sorted((ROOT / "version").glob("*/rf4_x64_Data")):
            assets = data_dir / "resources.assets"
            if assets.exists() and assets != direct:
                candidates.append(assets)
    except OSError:
        pass
    # 常见安装位置（如 D:\RF4_CN\rf4game\Game、Steam 库）也纳入探测，
    # 保证游戏更新后能直接从最新客户端提取鱼名映射。
    for data_dir in _extra_rf4_data_dirs():
        assets = data_dir / "resources.assets"
        if assets.exists() and assets not in candidates:
            candidates.append(assets)
    # 按客户端修改时间倒序：优先用最近更新的游戏数据。
    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    candidates.sort(key=_mtime, reverse=True)
    yield from candidates


def _cache_path(profile_name: str) -> Path:
    return CACHE_DIR / f"fish_labels_zh_{profile_name.replace('.', '_')}.json"


def _read_cache(cache_path: Path, resources_assets: Path) -> Optional[Dict[str, str]]:
    if not cache_path.exists():
        return None
    try:
        payload = json.loads(cache_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    stat = resources_assets.stat()
    if (
        payload.get("source_path") != str(resources_assets)
        or payload.get("source_size") != stat.st_size
        or payload.get("source_mtime_ns") != stat.st_mtime_ns
    ):
        return None

    labels = payload.get("labels")
    if not isinstance(labels, dict):
        return None
    return {str(key): str(value) for key, value in labels.items() if key and value}


def _read_cache_labels_unchecked(cache_path: Path) -> Optional[Dict[str, str]]:
    if not cache_path.exists():
        return None
    try:
        payload = json.loads(cache_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    labels = payload.get("labels")
    if not isinstance(labels, dict):
        return None
    return {str(key): str(value) for key, value in labels.items() if key and value}


def _read_labels_file_unchecked(path: Path) -> Optional[Dict[str, str]]:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if isinstance(payload, dict) and isinstance(payload.get("labels"), dict):
        labels = payload["labels"]
    elif isinstance(payload, dict):
        labels = payload
    else:
        return None
    return {str(key): str(value) for key, value in labels.items() if key and value}


def _write_cache(cache_path: Path, resources_assets: Path, labels: Dict[str, str]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    stat = resources_assets.stat()
    payload = {
        "source_path": str(resources_assets),
        "source_size": stat.st_size,
        "source_mtime_ns": stat.st_mtime_ns,
        "labels": labels,
    }
    cache_path.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


DEFAULT_FISH_GRADE_LABELS = {
    1: "不达标",
    2: "达标",
    3: "稀有★",
    4: "超级稀有◆",
}
DEFAULT_FISH_GRADE_BY_LINE_TYPE = {
    25: 3,
    26: 4,
}


def load_fish_grade_config() -> tuple[Dict[int, str], Dict[int, int]]:
    """Load readable grade labels while keeping safe protocol defaults."""
    labels = dict(DEFAULT_FISH_GRADE_LABELS)
    line_types = dict(DEFAULT_FISH_GRADE_BY_LINE_TYPE)
    try:
        payload = json.loads(BUNDLED_LABEL_PATH.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return labels, line_types

    raw_labels = payload.get("grade_labels", {}) if isinstance(payload, dict) else {}
    if isinstance(raw_labels, dict):
        for raw_grade, raw_label in raw_labels.items():
            try:
                grade = int(raw_grade)
            except (TypeError, ValueError):
                continue
            if grade in DEFAULT_FISH_GRADE_LABELS and isinstance(raw_label, str) and raw_label.strip():
                labels[grade] = raw_label.strip()

    raw_line_types = payload.get("line_type_grades", {}) if isinstance(payload, dict) else {}
    if isinstance(raw_line_types, dict):
        for raw_line_type, raw_grade in raw_line_types.items():
            try:
                line_type = int(raw_line_type)
                grade = int(raw_grade)
            except (TypeError, ValueError):
                continue
            if grade in labels:
                line_types[line_type] = grade
    return labels, line_types


def load_unlocalized_fish_keys() -> set[str]:
    """Return catalog keys for which the bundled game locale has no Chinese name."""
    try:
        payload = json.loads(BUNDLED_LABEL_PATH.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    raw_keys = payload.get("unlocalized_keys", []) if isinstance(payload, dict) else []
    if not isinstance(raw_keys, list):
        return set()
    result: set[str] = set()
    for value in raw_keys:
        if isinstance(value, str) and value:
            result.add(value)
    return result


@lru_cache(maxsize=None)
def load_fish_labels(profile_name: str, locale_id: str = "zh_CN") -> Dict[str, str]:
    cache_path = _cache_path(profile_name)
    for resources_assets in _candidate_resources_assets(profile_name):
        cached = _read_cache(cache_path, resources_assets)
        if cached is not None:
            return cached

        labels = extract_system_labels_from_resources(resources_assets, locale_id=locale_id)
        if labels:
            try:
                _write_cache(cache_path, resources_assets, labels)
            except OSError:
                pass
            return labels

    bundled = _read_labels_file_unchecked(BUNDLED_LABEL_PATH)
    if bundled is not None:
        return bundled

    cached = _read_cache_labels_unchecked(cache_path)
    if cached is not None:
        return cached

    for fallback_cache_path in sorted(CACHE_DIR.glob("fish_labels_zh_*.json"), reverse=True):
        fallback = _read_cache_labels_unchecked(fallback_cache_path)
        if fallback is not None:
            return fallback

    return {}

