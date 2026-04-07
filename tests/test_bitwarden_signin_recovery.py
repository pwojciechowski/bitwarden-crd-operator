import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


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

if "schedule" not in sys.modules:
    schedule_module = types.ModuleType("schedule")

    class _Every:
        @property
        def seconds(self):
            return self

        def do(self, *args, **kwargs):
            return None

    schedule_module.every = lambda *args, **kwargs: _Every()
    schedule_module.run_pending = lambda: None
    sys.modules["schedule"] = schedule_module

import bitwardenCrdOperator as operator  # noqa: E402


class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", str(message)))

    def warn(self, message):
        self.messages.append(("warn", str(message)))

    def error(self, message):
        self.messages.append(("error", str(message)))


class BitwardenSigninRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.logger = DummyLogger()
        self.original_auth_failures = operator.auth_failures
        operator.auth_failures = 0
        os.environ.pop("BW_HOST", None)
        os.environ.pop("BW_SESSION", None)
        os.environ.pop("BW_AUTH_FAILURE_THRESHOLD", None)
        os.environ.pop("BW_AUTH_COOLDOWN_SECONDS", None)
        operator.record_auth_success()

    def tearDown(self):
        operator.auth_failures = self.original_auth_failures
        os.environ.pop("BW_AUTH_FAILURE_THRESHOLD", None)
        os.environ.pop("BW_AUTH_COOLDOWN_SECONDS", None)
        os.environ.pop("BW_SESSION", None)
        operator.record_auth_success()

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_signin_success_resets_failure_counter(self, command_wrapper_mock):
        operator.auth_failures = 2
        command_wrapper_mock.side_effect = [
            {"success": True},
            {"data": {"template": {"status": "unlocked"}}},
        ]

        operator.bitwarden_signin(self.logger)

        self.assertEqual(operator.auth_failures, 0)

    @patch("bitwardenCrdOperator.recover_auth_state")
    @patch("bitwardenCrdOperator.command_wrapper")
    def test_signin_failure_below_threshold_does_not_trigger_recovery(
        self, command_wrapper_mock, recover_auth_state_mock
    ):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "3"
        command_wrapper_mock.return_value = None

        operator.bitwarden_signin(self.logger)

        self.assertEqual(operator.auth_failures, 1)
        recover_auth_state_mock.assert_not_called()

    @patch("bitwardenCrdOperator.recover_auth_state")
    @patch("bitwardenCrdOperator.command_wrapper")
    def test_recovery_runs_after_threshold_and_resets_counter(
        self, command_wrapper_mock, recover_auth_state_mock
    ):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "2"
        operator.auth_failures = 1
        command_wrapper_mock.side_effect = [
            None,
            {"success": True},
            {"data": {"template": {"status": "locked"}}},
            {"data": {"raw": "new-session"}},
        ]

        operator.bitwarden_signin(self.logger)

        recover_auth_state_mock.assert_called_once_with(self.logger)
        self.assertEqual(operator.auth_failures, 0)
        self.assertEqual(os.environ.get("BW_SESSION"), "new-session")

    @patch("bitwardenCrdOperator.sys.exit")
    @patch("bitwardenCrdOperator.recover_auth_state")
    @patch("bitwardenCrdOperator.command_wrapper")
    def test_recovery_failure_exits_process(
        self, command_wrapper_mock, recover_auth_state_mock, sys_exit_mock
    ):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "1"
        command_wrapper_mock.side_effect = [None, None]

        operator.bitwarden_signin(self.logger)

        recover_auth_state_mock.assert_called_once_with(self.logger)
        sys_exit_mock.assert_called_once_with(1)

    def test_invalid_threshold_uses_default_without_exception_control_flow(self):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "invalid"

        threshold = operator._auth_failure_threshold(self.logger)

        self.assertEqual(threshold, operator.AUTH_FAILURE_THRESHOLD)

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_recover_auth_state_clears_session_and_cache_file(
        self, command_wrapper_mock
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            data_file = Path(temp_dir) / ".config" / "Bitwarden CLI" / "data.json"
            data_file.parent.mkdir(parents=True, exist_ok=True)
            data_file.write_text("{ invalid", encoding="utf-8")
            os.environ["BW_SESSION"] = "stale-session"

            with patch(
                "bitwardenCrdOperator.os.path.expanduser", return_value=temp_dir
            ):
                operator.recover_auth_state(self.logger)

            self.assertNotIn("BW_SESSION", os.environ)
            self.assertFalse(data_file.exists())
            command_wrapper_mock.assert_called_once_with(
                self.logger, "logout", use_success=False
            )

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_status_failure_counts_as_auth_failure(self, command_wrapper_mock):
        command_wrapper_mock.side_effect = [
            {"success": True},
            None,
        ]

        operator.bitwarden_signin(self.logger)

        self.assertEqual(operator.auth_failures, 1)

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_already_logged_in_does_not_count_as_auth_failure(
        self, command_wrapper_mock
    ):
        command_wrapper_mock.side_effect = [
            {
                "success": False,
                "message": "You are already logged in as user@example.com.",
            },
            {"data": {"template": {"status": "unlocked"}}},
        ]

        operator.bitwarden_signin(self.logger)

        self.assertEqual(operator.auth_failures, 0)

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_configure_bw_host_recovers_marker_mismatch_with_actual_server(
        self, command_wrapper_mock
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            marker_file = Path(temp_dir) / ".bw_host"
            marker_file.write_text("https://stale-marker.example.com", encoding="utf-8")
            os.environ["BW_HOST"] = "https://expected.example.com"

            command_wrapper_mock.side_effect = [
                {
                    "success": True,
                    "data": {"template": "https://actual-other.example.com"},
                },
                {"success": True},
                {"success": True, "data": {"template": "https://expected.example.com"}},
            ]

            with patch(
                "bitwardenCrdOperator.os.path.expanduser", return_value=temp_dir
            ):
                operator._configure_bw_host(self.logger)

            self.assertEqual(
                marker_file.read_text(encoding="utf-8"),
                "https://expected.example.com",
            )
            command_wrapper_mock.assert_any_call(
                self.logger,
                "config server https://expected.example.com",
                use_success=False,
            )

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_auth_cooldown_blocks_repeated_auth_attempts(self, command_wrapper_mock):
        os.environ["BW_AUTH_COOLDOWN_SECONDS"] = "60"

        with patch("utils.utils.time.monotonic", return_value=100.0):
            operator.record_auth_failure()

        with patch("utils.utils.time.monotonic", return_value=105.0):
            operator.bitwarden_signin(self.logger)

        command_wrapper_mock.assert_not_called()
        self.assertEqual(operator.auth_failures, 1)

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_configured_bw_host_parses_cli_data_string_shape(
        self, command_wrapper_mock
    ):
        command_wrapper_mock.return_value = {
            "success": True,
            "data": {"object": "string", "data": "https://vault.example.com"},
        }

        configured_host = operator._configured_bw_host(self.logger)

        self.assertEqual(configured_host, "https://vault.example.com")

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_configure_bw_host_retries_with_logout_when_verification_fails(
        self, command_wrapper_mock
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["BW_HOST"] = "https://expected.example.com"
            command_wrapper_mock.side_effect = [
                {
                    "success": True,
                    "data": {
                        "object": "string",
                        "data": "https://bitwarden.com",
                    },
                },
                {"success": True},
                {
                    "success": True,
                    "data": {
                        "object": "string",
                        "data": "https://bitwarden.com",
                    },
                },
                {"success": True},
                {"success": True},
                {
                    "success": True,
                    "data": {
                        "object": "string",
                        "data": "https://expected.example.com",
                    },
                },
            ]

            with patch(
                "bitwardenCrdOperator.os.path.expanduser", return_value=temp_dir
            ):
                operator._configure_bw_host(self.logger)

        command_wrapper_mock.assert_any_call(
            self.logger,
            "logout",
            use_success=False,
        )


if __name__ == "__main__":
    unittest.main()
