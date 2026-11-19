#!/usr/bin/env python3
"""Unit tests untuk scripts/tg-callback-poller.py."""

import importlib.util
import os
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "tg-callback-poller.py")
SPEC = importlib.util.spec_from_file_location("tg_callback_poller", MODULE_PATH)
poller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(poller)


class TestTgCallbackPoller(unittest.TestCase):
    def setUp(self):
        poller.ALLOWED_CHAT_IDS = set()
        poller.ALLOWED_USER_IDS = set()

    def test_forward_success(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = poller.forward({"update_id": 101, "callback_query": {}}, webhook_url="http://test-webhook")
            self.assertTrue(res)

    def test_forward_failure_network(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            res = poller.forward({"update_id": 101, "callback_query": {}}, webhook_url="http://test-webhook")
            self.assertFalse(res)

    def test_forward_failure_non_2xx(self):
        mock_resp = MagicMock()
        mock_resp.status = 502
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = poller.forward({"update_id": 101, "callback_query": {}}, webhook_url="http://test-webhook")
            self.assertFalse(res)

    def test_process_updates_all_success(self):
        updates = [
            {"update_id": 101, "callback_query": {"id": "cq1"}},
            {"update_id": 102, "callback_query": {"id": "cq2"}},
        ]
        with patch.object(poller, "forward", return_value=True) as mock_fwd:
            offset, count, failed = poller.process_updates(updates)
            self.assertEqual(offset, 103)
            self.assertEqual(count, 2)
            self.assertFalse(failed)
            self.assertEqual(mock_fwd.call_count, 2)

    def test_process_updates_stops_and_retains_offset_on_failure(self):
        updates = [
            {"update_id": 201, "callback_query": {"id": "cq1"}},
            {"update_id": 202, "callback_query": {"id": "cq2"}},
            {"update_id": 203, "callback_query": {"id": "cq3"}},
        ]

        def side_effect(upd, webhook_url=None):
            return upd["update_id"] == 201  # 201 sukses, 202 gagal

        with patch.object(poller, "forward", side_effect=side_effect) as mock_fwd:
            offset, count, failed = poller.process_updates(updates, failure_counts={})
            # Offset harus tertahan di 202 agar Telegram tidak menghapusnya
            self.assertEqual(offset, 202)
            self.assertEqual(count, 1)
            self.assertTrue(failed)
            self.assertEqual(mock_fwd.call_count, 2)

    def test_process_updates_dead_letters_after_max_retries(self):
        updates = [
            {"update_id": 202, "callback_query": {"id": "cq2"}},
            {"update_id": 203, "callback_query": {"id": "cq3"}},
        ]
        counts = {}
        with patch.object(poller, "forward", side_effect=lambda u, webhook_url=None: u["update_id"] == 203):
            # Percobaan 1 & 2 menahan offset di 202
            off1, _, fail1 = poller.process_updates(updates, failure_counts=counts, max_retries=3)
            self.assertEqual(off1, 202)
            self.assertTrue(fail1)
            off2, _, fail2 = poller.process_updates(updates, failure_counts=counts, max_retries=3)
            self.assertEqual(off2, 202)
            self.assertTrue(fail2)
            # Percobaan 3 men-dead-letter 202 dan lanjut memproses 203
            off3, cnt3, fail3 = poller.process_updates(updates, failure_counts=counts, max_retries=3)
            self.assertEqual(off3, 204)
            self.assertEqual(cnt3, 2)
            self.assertFalse(fail3)

    def test_sender_allowlist_rejects_unauthorized_chat(self):
        updates = [
            {
                "update_id": 401,
                "callback_query": {"id": "cq1", "from": {"id": 999}, "message": {"chat": {"id": 111}}},
            },
            {
                "update_id": 402,
                "callback_query": {"id": "cq2", "from": {"id": 777}, "message": {"chat": {"id": 222}}},
            },
        ]
        with patch.object(poller, "forward", return_value=True) as mock_fwd:
            off, cnt, failed = poller.process_updates(
                updates,
                failure_counts={},
                allowed_chats={"222"},
                allowed_users={"777"},
            )
            self.assertEqual(off, 403)
            self.assertEqual(cnt, 2)
            self.assertFalse(failed)
            self.assertEqual(mock_fwd.call_count, 1)

    def test_sanitize_error_redacts_bot_token(self):
        self.assertNotIn("123456:SECRET_ABC", poller._sanitize_error("https://api.telegram.org/bot123456:SECRET_ABC/getUpdates"))

    def test_process_updates_skips_non_callback(self):
        updates = [
            {"update_id": 301, "message": {"text": "hello"}},
            {"update_id": 302, "callback_query": {"id": "cq1"}},
        ]
        with patch.object(poller, "forward", return_value=True) as mock_fwd:
            offset, count, failed = poller.process_updates(updates)
            self.assertEqual(offset, 303)
            self.assertEqual(count, 2)
            self.assertFalse(failed)
            self.assertEqual(mock_fwd.call_count, 1)

    def test_empty_updates(self):
        offset, count, failed = poller.process_updates([])
        self.assertIsNone(offset)
        self.assertEqual(count, 0)
        self.assertFalse(failed)


if __name__ == "__main__":
    unittest.main()
