# --- Fish localization ---
import json
import mmap
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Optional

PACKAGE_DIR = Path(__file__).resolve().parent
THIS_DIR = PACKAGE_DIR.parent
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


def _candidate_resources_assets(profile_name: str) -> Iterable[Path]:
    direct = ROOT / "version" / profile_name / "rf4_x64_Data" / "resources.assets"
    if direct.exists():
        yield direct

    for candidate in sorted((ROOT / "version").glob("*/rf4_x64_Data/resources.assets"), reverse=True):
        if candidate != direct:
            yield candidate


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

