"""rf4_core.sniffer：自动识别长期运行状态清理测试。"""
from __future__ import annotations

import unittest
from unittest import mock

from rf4_core import sniffer

from rf4_core.tests.sniffer.helpers import _ctx, _make_observer


class DiscoveryLifecycleTests(unittest.TestCase):
    def test_expired_retry_keys_are_removed(self) -> None:
        _ctx()
        observer = _make_observer()
        key = (("185.71.66.225", 9347), ("192.168.2.8", 40001))
        observer._retry_candidate_keys[key] = 0.0

        with mock.patch.object(sniffer.time, "monotonic", lambda: 100.0):
            observer._expire_candidates()

        self.assertNotIn(key, observer._retry_candidate_keys)

    def test_retry_keys_do_not_grow_without_limit(self) -> None:
        _ctx()
        observer = _make_observer()
        limit = sniffer.RETRY_CANDIDATE_MAX_ENTRIES
        observer._retry_candidate_keys = {
            (("10.0.0.1", index), ("10.0.0.2", 9000)): 0.0
            for index in range(limit)
        }
        new_key = (("10.0.0.3", 1), ("10.0.0.4", 9000))

        observer._add_retry_candidate_key(new_key)

        self.assertEqual(len(observer._retry_candidate_keys), limit)
        self.assertIn(new_key, observer._retry_candidate_keys)
