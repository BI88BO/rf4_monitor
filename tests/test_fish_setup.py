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


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _build_setup_payload(
    *,
    pre_flag_floats: tuple[float, ...] = (),
    post_flag_floats: tuple[float, ...] = (),
    include_flag: bool = True,
    flag_value: int = 1,
) -> bytes:
    """构造钓组上报载荷（0x34/0x38 float → 0x3C bool → 0x40.. float）。"""
    flag_byte = bytes([flag_value]) if include_flag else b""
    return (
        pack_arg_header(b"507", 1)
        + pack_guid_marker("11111111-1111-1111-1111-111111111111")
        + pack_object_header(123)
        + pack_guid_raw("22222222-2222-2222-2222-222222222222")
        + pack_short_string("perch")
        + bytes([4])
        + struct.pack("<f", 1.25)
        + pack_u32(262)
        + struct.pack("<" + "f" * len(pre_flag_floats), *pre_flag_floats)
        + flag_byte
        + struct.pack("<" + "f" * len(post_flag_floats), *post_flag_floats)
    )


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

    def test_parses_base_fields(self) -> None:
        setup = self._parse(_build_setup_payload())
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.fish_key, "perch")
        self.assertEqual(setup.weight_hint_raw, 262)
        self.assertAlmostEqual(setup.length_hint, 1.25)
        self.assertEqual(setup.setup_enum, 4)

    def test_flag_byte_read_as_bool(self) -> None:
        setup = self._parse(_build_setup_payload())
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertTrue(setup.stamina_flag)

    def test_flag_zero_reads_as_false(self) -> None:
        payload = _build_setup_payload(flag_value=0)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertFalse(setup.stamina_flag)

    def test_float_group_after_flag(self) -> None:
        floats = (0.5, 1.0, 2.0)
        payload = _build_setup_payload(pre_flag_floats=(10.0, 20.0), post_flag_floats=floats)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        # extra_floats 合并了 flag 前后的 float。
        self.assertEqual(
            tuple(round(v, 4) for v in setup.extra_floats), (10.0, 20.0, 0.5, 1.0, 2.0)
        )

    def test_pre_flag_floats_and_flag(self) -> None:
        payload = _build_setup_payload(pre_flag_floats=(10.0, 20.0), flag_value=1)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertTrue(setup.stamina_flag)
        self.assertEqual(tuple(round(v, 4) for v in setup.extra_floats), (10.0, 20.0))

    def test_no_extra_bytes_yields_empty_group(self) -> None:
        setup = self._parse(_build_setup_payload())
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.extra_floats, ())
        self.assertTrue(setup.stamina_flag)

    def test_truncated_float_ignored(self) -> None:
        payload = _build_setup_payload(pre_flag_floats=(1.0,))[:-2]
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertEqual(setup.extra_floats, ())

    def test_missing_flag_byte(self) -> None:
        # 无 flag 字节时（载荷在 weight 后直接结束或直接 float），flag 保持 None。
        payload = _build_setup_payload(include_flag=False)
        setup = self._parse(payload)
        self.assertIsNotNone(setup)
        assert setup is not None
        self.assertIsNone(setup.stamina_flag)
        self.assertEqual(setup.extra_floats, ())


if __name__ == "__main__":
    unittest.main()