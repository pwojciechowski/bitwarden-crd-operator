import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _fake_startup(*args, **kwargs):
    def _decorator(fn):
        return fn

    return _decorator


if "kopf" not in sys.modules:
    kopf_module = types.ModuleType("kopf")
    kopf_module.on = types.SimpleNamespace(startup=_fake_startup)
    kopf_module.append_owner_reference = lambda *args, **kwargs: None
    sys.modules["kopf"] = kopf_module

if "kubernetes" not in sys.modules:
    kubernetes_module = types.ModuleType("kubernetes")
    kubernetes_module.client = types.SimpleNamespace(
        CoreV1Api=lambda: None,
        V1ObjectMeta=lambda **kwargs: kwargs,
    )
    sys.modules["kubernetes"] = kubernetes_module

from utils import utils  # noqa: E402


class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", str(message)))

    def warn(self, message):
        self.messages.append(("warn", str(message)))


class UtilsAuthAndCommandWrapperTests(unittest.TestCase):
    def setUp(self):
        self.logger = DummyLogger()
        os.environ.pop("BW_AUTH_COOLDOWN_SECONDS", None)
        utils.record_auth_success()

    def tearDown(self):
        os.environ.pop("BW_AUTH_COOLDOWN_SECONDS", None)
        os.environ.pop("BW_SESSION", None)
        utils.record_auth_success()

    @patch("utils.utils.subprocess.Popen")
    def test_command_wrapper_non_json_stdout_returns_none_without_crash(
        self, popen_mock
    ):
        process = MagicMock()
        process.communicate.return_value = (b"not-json", b"")
        process.returncode = 0
        popen_mock.return_value = process

        result = utils.command_wrapper(self.logger, "status")

        self.assertIsNone(result)
        self.assertTrue(
            any("non-JSON output" in message for _, message in self.logger.messages)
        )

    @patch("utils.utils.command_wrapper")
    def test_unlock_bw_cooldown_blocks_repeated_attempts(self, command_wrapper_mock):
        os.environ["BW_AUTH_COOLDOWN_SECONDS"] = "30"
        command_wrapper_mock.return_value = None

        with patch("utils.utils.time.monotonic", return_value=10.0):
            with self.assertRaises(utils.BitwardenCommandException):
                utils.unlock_bw(self.logger)

        with patch("utils.utils.time.monotonic", return_value=20.0):
            with self.assertRaises(utils.BitwardenCommandException):
                utils.unlock_bw(self.logger)

        self.assertEqual(command_wrapper_mock.call_count, 1)

    @patch("utils.utils.command_wrapper")
    def test_unlock_bw_unauthenticated_logs_in_and_unlocks(self, command_wrapper_mock):
        command_wrapper_mock.side_effect = [
            {"data": {"template": {"status": "unauthenticated"}}},
            {"success": True},
            {"data": {"template": {"status": "locked"}}},
            {"data": {"raw": "fresh-session"}},
        ]

        utils.unlock_bw(self.logger)

        self.assertEqual(os.environ.get("BW_SESSION"), "fresh-session")
        command_wrapper_mock.assert_any_call(
            self.logger,
            "login --apikey",
            use_success=False,
        )

    @patch("utils.utils.command_wrapper")
    def test_unlock_bw_unauthenticated_handles_already_logged_in(
        self, command_wrapper_mock
    ):
        command_wrapper_mock.side_effect = [
            {"data": {"template": {"status": "unauthenticated"}}},
            {
                "success": False,
                "message": "You are already logged in as user@example.com.",
            },
            {"data": {"template": {"status": "locked"}}},
            {"data": {"raw": "fresh-session"}},
        ]

        utils.unlock_bw(self.logger)

        self.assertEqual(os.environ.get("BW_SESSION"), "fresh-session")


if __name__ == "__main__":
    unittest.main()
