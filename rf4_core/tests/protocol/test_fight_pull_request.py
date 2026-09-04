"""rf4_core.protocol：fight_pull（拉线结算）请求解析测试。"""
from __future__ import annotations

import unittest

from rf4_core.protocol import (
    build_request_envelope,
    get_profile,
    pack_arg_header,
    pack_guid_marker,
    pack_marked_u32,
    parse_envelope,
    parse_fight_pull_request,
)


class ParseFightPullRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        from rf4_core.protocol import get_profile

        self.profile = get_profile("4.0.24799")

    def _parse(self, payload: bytes):
        envelope = parse_envelope(
            build_request_envelope(
                call_id=10,
                main_cmd=self.profile.fishing_main_cmd,
                sub_cmd=self.profile.fight_pull_sub_cmd,
                payload=payload,
            )
        )
        assert envelope is not None
        return parse_fight_pull_request(envelope, self.profile)

    def test_parses_gear_and_tick(self) -> None:
        payload = (
            pack_arg_header(b"507", 3)
            + pack_guid_marker("5a43c383-1111-1111-1111-111111111111")
            + pack_marked_u32(353)
        )
        pull = self._parse(payload)
        self.assertIsNotNone(pull)
        assert pull is not None
        self.assertEqual(pull.fishing_gear_id, "5a43c383-1111-1111-1111-111111111111")
        self.assertEqual(pull.tick, 353)

    def test_missing_gear_returns_none(self) -> None:
        payload = pack_arg_header(b"507", 3) + pack_marked_u32(353)
        self.assertIsNone(self._parse(payload))

    def test_other_sub_cmd_returns_none(self) -> None:
        envelope = parse_envelope(
            build_request_envelope(
                call_id=10,
                main_cmd=self.profile.fishing_main_cmd,
                sub_cmd=self.profile.fight_load_sub_cmd,
                payload=pack_arg_header(b"507", 3),
            )
        )
        assert envelope is not None
        self.assertIsNone(parse_fight_pull_request(envelope, self.profile))
