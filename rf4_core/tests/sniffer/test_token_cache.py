"""rf4_core.sniffer：token 磁盘缓存测试。"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from rf4_core import sniffer
from rf4_core.protocol import RC4Stream, build_ack_frame, build_frame, build_request_envelope

from rf4_core.tests.sniffer.helpers import TOKEN, _ctx, _make_observer


class TokenCacheTests(unittest.TestCase):
    def test_save_and_load_roundtrip(self) -> None:
        import tempfile

        _ctx()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tokens.json"
            self.assertTrue(sniffer._save_cached_token("1.2.3.4:9000", TOKEN, path=path))
            loaded = sniffer._load_cached_tokens(path)
            self.assertEqual(loaded, {"1.2.3.4:9000": TOKEN})

    def test_invalid_token_not_saved(self) -> None:
        import tempfile

        _ctx()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tokens.json"
            self.assertFalse(sniffer._save_cached_token("1.2.3.4:9000", "", path=path))
            self.assertFalse(sniffer._save_cached_token("1.2.3.4:9000", "not-a-valid-token", path=path))
            self.assertEqual(sniffer._load_cached_tokens(path), {})

    def test_expired_cache_ignored(self) -> None:
        import tempfile

        _ctx()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tokens.json"
            sniffer._save_cached_token("1.2.3.4:9000", TOKEN, path=path)
            # 超过有效期后应视为无缓存：读取时间远晚于保存时间
            now = sniffer.time.time() + sniffer.TOKEN_CACHE_MAX_AGE_SECONDS + 30
            loaded = sniffer._load_cached_tokens(path, now=now)
            self.assertEqual(loaded, {})

    def test_handoff_bootstrap_falls_back_to_disk_token_cache(self) -> None:
        import tempfile

        _ctx()
        observer = _make_observer()
        ref = RC4Stream(TOKEN.encode())
        plain = build_request_envelope(call_id=9, main_cmd=14, sub_cmd=4, payload=b"cache")
        encrypted = build_frame(0, 700, ref.crypt(plain))
        stream = build_ack_frame(11) + encrypted

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "tokens.json"
            sniffer._save_cached_token("185.71.66.225:9400", TOKEN, path=cache_path)
            client = ("192.168.2.8", 34000)
            server = ("185.71.66.225", 9400)
            sorted_key = (("185.71.66.225", 9400), ("192.168.2.8", 34000))
            with mock.patch.object(sniffer, "_load_cached_tokens", return_value={"185.71.66.225:9400": TOKEN}):
                observer._handle_auto_packet(
                    src=client[0], sport=client[1], dst=server[0], dport=server[1],
                    seq=8000, payload=b"", flags=0x02,
                )
                observer._handle_auto_packet(
                    src=server[0], sport=server[1], dst=client[0], dport=client[1],
                    seq=9000, payload=stream, flags=0x18,
                )
            self.assertIn(sorted_key, observer._auto_sessions)
            session = observer._auto_sessions[sorted_key][0]
            self.assertGreater(session.valid_business_frames, 0)

    def test_handoff_bootstrap_falls_back_to_cached_token_from_other_endpoint(self) -> None:
        import tempfile

        _ctx()
        observer = _make_observer()
        ref = RC4Stream(TOKEN.encode())
        plain = build_request_envelope(call_id=9, main_cmd=14, sub_cmd=4, payload=b"cache")
        encrypted = build_frame(0, 700, ref.crypt(plain))
        stream = build_ack_frame(11) + encrypted

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "tokens.json"
            sniffer._save_cached_token("91.132.228.133:9200", TOKEN, path=cache_path)
            client = ("192.168.2.8", 34000)
            server = ("185.71.66.225", 9400)
            sorted_key = (("185.71.66.225", 9400), ("192.168.2.8", 34000))
            with mock.patch.object(sniffer, "_load_cached_tokens", return_value={"91.132.228.133:9200": TOKEN}):
                observer._handle_auto_packet(
                    src=client[0], sport=client[1], dst=server[0], dport=server[1],
                    seq=8000, payload=b"", flags=0x02,
                )
                observer._handle_auto_packet(
                    src=server[0], sport=server[1], dst=client[0], dport=client[1],
                    seq=9000, payload=stream, flags=0x18,
                )
            self.assertIn(sorted_key, observer._auto_sessions)
            session = observer._auto_sessions[sorted_key][0]
            self.assertGreater(session.valid_business_frames, 0)
