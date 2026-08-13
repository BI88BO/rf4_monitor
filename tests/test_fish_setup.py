from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rf4_core.protocol import (
    build_request_envelope,
    pack_arg_header,
    pack_guid_marker,
    pack_guid_raw,
    pack_object_header,
    pack_short_string,
    parse_envelope,
    parse_fish_setup_push,
)


def _build_setup_payload(*, extra_floats: tuple[float, ...] = ()) -> bytes:
    payload = (
        pack_arg_header(b"507", 1)
        + pack_guid_marker("11111111-1111-1111-1111-111111111111")
        + pack_object_header(123)
        + pack_guid_raw("22222222-2222-2222-2222-222222222222")
        + pack_short_string("perch")
        + bytes([4])
        + struct.pack("<f", 1.25)
        + pack_u32(262)
    )
    if extra_floats:
        payload += struct.pack("<" + "f" * len(extra_floats), *extra_floats)
    return payload


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


class ParseFishSetupPushTests(unittest.TestCase):
    def setUp(self) -> None:
        from rf4_core.protocol import get_profile

        self.profile = get_profile("4.0.24799")

    def _parse(self, payload: bytes):
        envelope = parse_envelope(
            build_request_envelope(
                call_id=10,
                main_cmd=self.profile.fishing_main_cmd,
                sub_cmd=self.profile.fish_setup_push_sub_cmd,
                payload=payload,
            )
        )
        assert envelope is not None
        return parse_fish_setup_push(envelope, self.profile)

    def test_parses_extra_float_group_after_weight(self) -> None:
        setup = self._parse(_build_setup_payload(extra_floats=(0.5, 1.0, 2.0)))
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.fish_key, "perch")
        self.assertEqual(setup.weight_hint_raw, 262)
        self.assertAlmostEqual(setup.length_hint, 1.25)
        self.assertEqual(tuple(round(v, 4) for v in setup.extra_floats), (0.5, 1.0, 2.0))

    def test_no_extra_floats_yields_empty_tuple(self) -> None:
        setup = self._parse(_build_setup_payload())
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.extra_floats, ())

    def test_missing_float_bytes_ignored(self) -> None:
        # 截断的载荷：weight 之后只有 2 字节，不是完整 float → 忽略。
        payload = _build_setup_payload(extra_floats=(1.0,))[:-2]
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.extra_floats, ())

    def test_float_group_matches_fish_setup_class_layout(self) -> None:
        # 对照 dump.cs 中鱼设置类 gkfghccolil 的字段布局：
        # 0x2C length float / 0x30 weight int / 0x34..0x70 后续 float 组。
        setup = self._parse(_build_setup_payload(extra_floats=(11.0, 12.0, 13.0, 14.0)))
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(len(setup.extra_floats), 4)


if __name__ == "__main__":
    unittest.main()