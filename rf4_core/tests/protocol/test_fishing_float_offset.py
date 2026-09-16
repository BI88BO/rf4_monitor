"""fishing_frame_float_offset：跳过参数头/GUID，避免从 GUID 字节扫出伪浮点组。"""
from __future__ import annotations

import unittest

from rf4_core.protocol import (
    fishing_frame_float_offset,
    pack_arg_header,
    pack_guid_marker,
)

# 真实 14/7 位置上报帧（1 号杆 e74679d9）。GUID 的 16 字节恰好能拼出
# 伪组 (29171.64,-18.41,3.07e-05)，不跳过 GUID 就会恒定显示 18.41 米。
REAL_POSITION_PAYLOAD = bytes.fromhex(
    "030335323403000c"
    "d97946e7e346ca4693c1f2b100383f51"
    "011400000058f4d1436d6bbbbfa8862f44076c766c395f31398b07000000000000"
    "dba1583ef0c7073ff12e123f167b7641a090bd3f01ab624c440145010000baa4d243"
    "4653243f55533344008007c20000d4c000000000103203000001"
)


class FishingFrameFloatOffsetTests(unittest.TestCase):
    def test_skips_arg_header_and_gear_guid(self) -> None:
        # 参数头 7 字节 + 0x0C 标记 + 16 字节 GUID = 24。
        self.assertEqual(fishing_frame_float_offset(REAL_POSITION_PAYLOAD), 24)

    def test_skips_two_guids_when_fish_setup_present(self) -> None:
        payload = (
            pack_arg_header(b"524", 3)
            + pack_guid_marker("e74679d9-46e3-46ca-93c1-f2b100383f51")
            + pack_guid_marker("11111111-2222-3333-4444-555555555555")
        )
        self.assertEqual(fishing_frame_float_offset(payload), len(payload))

    def test_falls_back_to_zero_without_arg_header(self) -> None:
        self.assertEqual(fishing_frame_float_offset(b"\x00\x01\x02"), 0)


if __name__ == "__main__":
    unittest.main()
