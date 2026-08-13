from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core import bridge as bridge_mod
from rf4_core import game_catalog as gc
from rf4_core.bridge import FlowSession, RF4ChatBridge
from rf4_core.protocol import (
    build_request_envelope,
    build_response_envelope,
    get_profile,
    parse_envelope,
)


def build_gear_pkg(config_type_id: int, subtype: int, config_id: int, system_id: str) -> bytes:
    header = b"\x01" + struct.pack("<I", config_type_id) + bytes([subtype])
    sid = system_id.encode("ascii")
    base = bytes([0]) + struct.pack("<i", config_id) + bytes([len(sid)]) + sid
    return header + b"\x00" * 12 + base


def encrypt_cache(pkg: bytes) -> tuple[bytes, str]:
    """Encrypt a gear config package like the native client, returning (encrypted, sha1)."""
    plain_hash = hashlib.sha1(pkg).hexdigest()
    seed = gc._config_cache_seed_candidates(plain_hash)[3][1]
    return gc._transform_config_cache(pkg, seed, reverse=False), plain_hash


def pack_string_array(values: list[str]) -> bytes:
    body = b"\x04" + struct.pack("<H", len(values))
    for value in values:
        body += struct.pack("<i", len(value)) + value.encode("ascii")
    return body


class ConfigCacheDecryptTests(unittest.TestCase):
    def tearDown(self) -> None:
        bridge_mod.ctx = getattr(self, "_prev_ctx", None)

    def _bridge(self) -> RF4ChatBridge:
        self._prev_ctx = bridge_mod.ctx
        bridge_mod.ctx = SimpleNamespace(
            options=SimpleNamespace(
                rf4_verbose_logging=False,
                rf4_log_telemetry=True,
                rf4_telemetry_categories="all",
                rf4_event_bridge_port=0,
            )
        )
        return RF4ChatBridge()

    def test_hash_capture_and_cache_decrypt(self) -> None:
        pkg = build_gear_pkg(12020, 1, 9061, "hook_a_9061") + build_gear_pkg(
            12024, 1, 3571, "mono_b_3571"
        )
        encrypted, plain_hash = encrypt_cache(pkg)
        cache = Path(self._tmp()) / "test_c0001.dat"
        cache.write_bytes(encrypted)

        bridge = self._bridge()
        saved = gc.local_config_cache_candidates
        gc.local_config_cache_candidates = lambda **kw: [cache]
        try:
            bridge._load_gear_config_from_cache()
            self.assertEqual(len(bridge._gear_config_by_id), 0)

            envelope = parse_envelope(
                build_request_envelope(
                    call_id=7,
                    main_cmd=1,
                    sub_cmd=5,
                    payload=pack_string_array([plain_hash]),
                )
            )
            assert envelope is not None
            bridge._remember_config_version_hashes(None, envelope.payload)
            self.assertEqual(bridge._gear_config_hashes, [plain_hash])

            bridge._load_gear_config_from_cache()
            self.assertEqual(len(bridge._gear_config_by_id), 2)
            hook = bridge._gear_config_by_id.get(9061)
            line = bridge._gear_config_by_id.get(3571)
            self.assertIsNotNone(hook)
            self.assertIsNotNone(line)
            assert hook is not None and line is not None
            self.assertEqual(hook["system_id"], "hook_a_9061")
            self.assertEqual(hook["group_key"], "hook")
            self.assertEqual(line["system_id"], "mono_b_3571")
            self.assertEqual(line["group_key"], "line_mono")
        finally:
            gc.local_config_cache_candidates = saved

    def test_handle_server_frame_decrypts_cache_from_response(self) -> None:
        pkg = build_gear_pkg(12020, 1, 9061, "hook_a_9061") + build_gear_pkg(
            12024, 1, 3571, "mono_b_3571"
        )
        encrypted, plain_hash = encrypt_cache(pkg)
        cache = Path(self._tmp()) / "test_c0001.dat"
        cache.write_bytes(encrypted)

        bridge = self._bridge()
        saved = gc.local_config_cache_candidates
        gc.local_config_cache_candidates = lambda **kw: [cache]
        try:
            session = FlowSession(profile=get_profile("4.0.24799"))
            # client requests configs_version (call_id=9), then server responds
            request = build_request_envelope(call_id=9, main_cmd=1, sub_cmd=5, payload=b"\x04\x00\x00")
            bridge._track_rpc_request_command(session, request)
            bridge._handle_client_frame(session, request)
            response = build_response_envelope(call_id=9, payload=pack_string_array([plain_hash]))
            bridge._handle_server_frame(session, response)
            self.assertEqual(bridge._gear_config_hashes, [plain_hash])
            self.assertEqual(len(bridge._gear_config_by_id), 2)
            self.assertIn(9061, bridge._gear_config_by_id)
            self.assertIn(3571, bridge._gear_config_by_id)
        finally:
            gc.local_config_cache_candidates = saved

    def test_passive_tracking_enables_hash_capture(self) -> None:
        """被动抓包路径：sniffer 现会先调用 _track_rpc_request_command，1/5 请求因此可反查。"""
        pkg = build_gear_pkg(12020, 1, 9061, "hook_a_9061") + build_gear_pkg(
            12024, 1, 3571, "mono_b_3571"
        )
        encrypted, plain_hash = encrypt_cache(pkg)
        cache = Path(self._tmp()) / "test_c0001.dat"
        cache.write_bytes(encrypted)

        bridge = self._bridge()
        saved = gc.local_config_cache_candidates
        gc.local_config_cache_candidates = lambda **kw: [cache]
        try:
            session = FlowSession(profile=get_profile("4.0.24799"))
            request = build_request_envelope(call_id=9, main_cmd=1, sub_cmd=5, payload=b"\x04\x00\x00")
            bridge._track_rpc_request_command(session, request)
            bridge._handle_client_frame(session, request)
            response = build_response_envelope(call_id=9, payload=pack_string_array([plain_hash]))
            bridge._handle_server_frame(session, response)
            self.assertEqual(bridge._gear_config_hashes, [plain_hash])
            self.assertIn(9061, bridge._gear_config_by_id)
            self.assertIn(3571, bridge._gear_config_by_id)
        finally:
            gc.local_config_cache_candidates = saved

    def test_item_id_resolves_to_gear_chinese_name(self) -> None:
        bridge = self._bridge()
        bridge._gear_config_by_id[5274] = {
            "config_id": 5274,
            "system_id": "spin_5274",
            "group_key": "reel_other",
            "attributes": {},
        }
        config = bridge._gear_config_by_id_lookup(5274)
        self.assertIsNotNone(config)
        assert config is not None
        self.assertEqual(config["catalog_name"], "Turion SW 30000")
        self.assertIn("Turion SW 30000", bridge._format_item_id(5274, object_type_id=149))

    def test_system_item_name_prefix_fallback(self) -> None:
        """实例 system_id(带后缀) 应回退到基础 model 名。"""
        bridge = self._bridge()
        self.assertEqual(
            bridge._format_system_item_name("tele_10175_5_9"),
            '"Soul Pole 5"(tele_10175_5 变体)',
        )
        self.assertEqual(
            bridge._format_system_item_name("spin_6115_g"),
            '"Mayor III 3000S"(spin_6115 变体)',
        )
        # 无基础名时回退 family
        self.assertIn("Victory", bridge._format_system_item_name("spin_10252_M70ML"))

    def _tmp(self) -> Path:
        return Path(tempfile.mkdtemp(prefix="rf4_test_"))


if __name__ == "__main__":
    unittest.main()