import asyncio
import inspect
import os
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _fake_startup(*args, **kwargs):
    def _decorator(fn):
        return fn

    return _decorator


if "kopf" not in sys.modules:
    kopf_module = types.ModuleType("kopf")
    kopf_module.on = types.SimpleNamespace(startup=_fake_startup, probe=_fake_startup)
    kopf_module.PermanentError = type("PermanentError", (Exception,), {})

    class _TemporaryError(Exception):
        def __init__(self, message="", delay=60):
            super().__init__(message)
            self.delay = delay

    kopf_module.TemporaryError = _TemporaryError
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
        operator._warned_settings.clear()
        os.environ.pop("BW_HOST", None)
        os.environ.pop("BW_SESSION", None)
        os.environ.pop("BW_AUTH_FAILURE_THRESHOLD", None)
        os.environ.pop("BW_AUTH_COOLDOWN_SECONDS", None)
        operator.record_auth_success()
        # A real os._exit would end the test run without a report.
        exit_patcher = patch(
            "bitwardenCrdOperator.os._exit",
            side_effect=AssertionError("unexpected os._exit"),
        )
        exit_patcher.start()
        self.addCleanup(exit_patcher.stop)

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
            {"data": {"template": {"status": "unauthenticated"}}},
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
            {"data": {"template": {"status": "unauthenticated"}}},
            {"success": True},
            {"data": {"template": {"status": "locked"}}},
            {"data": {"raw": "new-session"}},
        ]

        operator.bitwarden_signin(self.logger)

        recover_auth_state_mock.assert_called_once_with(self.logger, reset_cli_data=False)
        self.assertEqual(operator.auth_failures, 0)
        self.assertEqual(os.environ.get("BW_SESSION"), "new-session")

    @patch("bitwardenCrdOperator.os._exit")
    @patch("bitwardenCrdOperator.recover_auth_state")
    @patch("bitwardenCrdOperator.command_wrapper")
    def test_recovery_failure_exits_process(
        self, command_wrapper_mock, recover_auth_state_mock, os_exit_mock
    ):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "1"
        command_wrapper_mock.return_value = None

        operator.bitwarden_signin(self.logger)

        self.assertEqual(
            recover_auth_state_mock.call_args_list,
            [
                call(self.logger, reset_cli_data=False),
                call(self.logger, reset_cli_data=True),
            ],
        )
        os_exit_mock.assert_called_once_with(1)

    def test_recovery_resets_cli_data_only_after_a_local_state_failure(self):
        # Geekvetica#108 B4: data.json holds the device ID, so deleting it on
        # every recovery logged in as a new device and sent an email each time.
        local_failures = [
            "Failed to get bw status",
            "Unexpected bw status: unknown",
            "Failed to read session token",
            "bw is configured for https://vault.bitwarden.com, not BW_HOST",
        ]
        for error in local_failures:
            with self.subTest(error=error):
                calls, exit_mock = self._recover_with_login_results(
                    [(False, operator.LOGIN_FAILED), (False, error), (True, "")]
                )

                self.assertEqual(
                    calls,
                    [
                        "configure_host", "login",
                        "recover", "configure_host", "recovery_login",
                        "reset", "configure_host", "recovery_login",
                    ],
                )
                self.assertIn(
                    ("error", f"Authentication recovery failed (with kept CLI data): {error}"),
                    self.logger.messages,
                )
                self.assertEqual(operator.auth_failures, 0)
                exit_mock.assert_not_called()

    def test_recovery_keeps_cli_data_when_the_server_refuses_login_or_unlock(self):
        # Both talk to Vaultwarden after a logout (unlock verifies the password
        # there): an outage or a rejected credential is not fixed by a reset,
        # which would only cost the device ID. Exit and let the pod restart.
        for error in (operator.LOGIN_FAILED, operator.UNLOCK_FAILED):
            with self.subTest(error=error):
                calls, exit_mock = self._recover_with_login_results(
                    [(False, operator.LOGIN_FAILED), (False, error)]
                )

                self.assertEqual(
                    calls,
                    ["configure_host", "login", "recover", "configure_host", "recovery_login"],
                )
                exit_mock.assert_called_once_with(1)

    def _recover_with_login_results(self, results):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "1"
        operator.auth_failures = 0
        self.logger = DummyLogger()
        calls = []
        attempts = iter(results)

        def login(logger, skip_cooldown=False):
            calls.append("recovery_login" if skip_cooldown else "login")
            return next(attempts)

        with patch(
            "bitwardenCrdOperator.recover_auth_state",
            side_effect=lambda logger, reset_cli_data=False: calls.append(
                "reset" if reset_cli_data else "recover"
            ),
        ), patch(
            "bitwardenCrdOperator._configure_bw_host",
            side_effect=lambda logger: calls.append("configure_host"),
        ), patch(
            "bitwardenCrdOperator._login_and_unlock", side_effect=login
        ), patch("bitwardenCrdOperator.os._exit") as exit_mock:
            operator.bitwarden_signin(self.logger)
        return calls, exit_mock

    @patch("bitwardenCrdOperator._login_and_unlock")
    @patch("bitwardenCrdOperator._configure_bw_host")
    @patch("bitwardenCrdOperator.recover_auth_state")
    def test_recovery_reconfigures_host_before_recovery_login(
        self, recover_auth_state_mock, configure_host_mock, login_mock
    ):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "1"
        calls = []
        recover_auth_state_mock.side_effect = lambda logger, reset_cli_data=False: calls.append(
            "reset" if reset_cli_data else "recover"
        )
        configure_host_mock.side_effect = lambda logger: calls.append("configure_host")

        def login(logger, skip_cooldown=False):
            calls.append("recovery_login" if skip_cooldown else "login")
            return (skip_cooldown, None if skip_cooldown else "bw login failed")

        login_mock.side_effect = login

        operator.bitwarden_signin(self.logger)

        self.assertEqual(
            calls,
            ["configure_host", "login", "recover", "configure_host", "recovery_login"],
        )

    def test_invalid_threshold_uses_default_without_exception_control_flow(self):
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "invalid"

        threshold = operator._auth_failure_threshold(self.logger)

        self.assertEqual(threshold, operator.AUTH_FAILURE_THRESHOLD)

    def _recover_with_cli_data_file(self, **kwargs):
        with tempfile.TemporaryDirectory() as temp_dir:
            data_file = Path(temp_dir) / ".config" / "Bitwarden CLI" / "data.json"
            data_file.parent.mkdir(parents=True, exist_ok=True)
            data_file.write_text("{ invalid", encoding="utf-8")
            os.environ["BW_SESSION"] = "stale-session"

            with patch(
                "bitwardenCrdOperator.os.path.expanduser", return_value=temp_dir
            ), patch("bitwardenCrdOperator.command_wrapper") as command_wrapper_mock:
                operator.recover_auth_state(self.logger, **kwargs)

            self.assertNotIn("BW_SESSION", os.environ)
            command_wrapper_mock.assert_called_once_with(
                self.logger, "logout", use_success=False
            )
            return data_file.exists()

    def test_recover_auth_state_logs_out_and_keeps_the_cli_data_file(self):
        self.assertTrue(self._recover_with_cli_data_file())

    def test_recover_auth_state_with_reset_removes_the_cli_data_file(self):
        self.assertFalse(self._recover_with_cli_data_file(reset_cli_data=True))

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_status_failure_counts_as_auth_failure(self, command_wrapper_mock):
        command_wrapper_mock.side_effect = [None]

        operator.bitwarden_signin(self.logger)

        self.assertEqual(operator.auth_failures, 1)

    @patch("bitwardenCrdOperator.recover_auth_state")
    @patch("bitwardenCrdOperator.command_wrapper")
    def test_scheduled_relogin_while_unlocked_does_not_count_as_auth_failure(
        self, command_wrapper_mock, recover_auth_state_mock
    ):
        # Like the real command_wrapper: bw login exits 1 with "You are
        # already logged in" while a session exists, and a non-zero exit
        # returns None, not the JSON.
        responses = {"status": {"data": {"template": {"status": "unlocked"}}}}
        command_wrapper_mock.side_effect = (
            lambda logger, command, *args, **kwargs: responses.get(command)
        )
        os.environ["BW_AUTH_FAILURE_THRESHOLD"] = "3"

        for _ in range(3):
            operator.bitwarden_signin(self.logger)

        self.assertEqual(operator.auth_failures, 0)
        recover_auth_state_mock.assert_not_called()

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_malformed_or_unknown_status_counts_as_auth_failure(
        self, command_wrapper_mock
    ):
        for status_output in (
            {"success": True, "data": None},
            {"success": True, "data": {"template": None}},
            {"success": True, "data": {"template": {"status": "weird"}}},
        ):
            with self.subTest(status_output=status_output):
                operator.auth_failures = 0
                operator.record_auth_success()
                command_wrapper_mock.reset_mock()
                command_wrapper_mock.side_effect = [status_output]

                operator.bitwarden_signin(self.logger)

                self.assertEqual(operator.auth_failures, 1)
                self.assertEqual(command_wrapper_mock.call_count, 1)

    @patch("bitwardenCrdOperator.command_wrapper")
    def test_logged_in_but_locked_unlocks_without_logging_in(
        self, command_wrapper_mock
    ):
        command_wrapper_mock.side_effect = [
            {"data": {"template": {"status": "locked"}}},
            {"data": {"raw": "new-session"}},
        ]

        operator.bitwarden_signin(self.logger)

        self.assertEqual(operator.auth_failures, 0)
        self.assertEqual(os.environ.get("BW_SESSION"), "new-session")
        commands = [c.args[1] for c in command_wrapper_mock.call_args_list]
        self.assertNotIn("login --apikey", commands)

    @patch("utils.utils.command_wrapper")
    @patch("bitwardenCrdOperator.command_wrapper")
    def test_api_key_login_is_refused_when_bw_points_at_another_server(
        self, command_wrapper_mock, utils_command_wrapper_mock
    ):
        # Geekvetica#108: after a data.json reset the CLI pointed at
        # bitwarden.com and the API key went there ~300 times.
        os.environ["BW_HOST"] = "https://vault.example.com"
        self.addCleanup(os.environ.pop, "BW_HOST", None)
        responses = {
            "status": {"data": {"template": {"status": "unauthenticated"}}},
            "config server": {
                "success": True,
                "data": {"object": "string", "data": "https://vault.bitwarden.com"},
            },
        }
        for mock in (command_wrapper_mock, utils_command_wrapper_mock):
            mock.side_effect = (
                lambda logger, command, *args, **kwargs: responses.get(command)
            )

        signin_ok, signin_error = operator._login_and_unlock(self.logger)

        self.assertFalse(signin_ok)
        self.assertIn("server", signin_error)
        commands = [
            c.args[1]
            for mock in (command_wrapper_mock, utils_command_wrapper_mock)
            for c in mock.call_args_list
        ]
        self.assertNotIn("login --apikey", commands)
        self.assertGreater(operator.auth_cooldown_remaining(self.logger), 0)

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


    def _probe_at(self, sync_age):
        with patch("bitwardenCrdOperator.seconds_since_last_sync", return_value=sync_age):
            return asyncio.run(operator.bw_sync_health(logger=self.logger))

    def test_probe_runs_on_the_event_loop_not_in_the_handler_thread_pool(self):
        # kopf runs a sync handler in its executor, which the CR timers fill
        # during every pass: /healthz then missed the kubelet's 1 s timeout.
        self.assertTrue(inspect.iscoroutinefunction(operator.bw_sync_health))

    def test_probe_turns_an_unexpected_error_into_a_failed_probe(self):
        # kopf retries any other exception every 60 s while /healthz waits.
        with patch(
            "bitwardenCrdOperator.seconds_since_last_sync",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertRaises(operator.kopf.PermanentError):
                asyncio.run(operator.bw_sync_health(logger=self.logger))

    def test_probe_ignores_an_unusable_sync_interval(self):
        self.addCleanup(os.environ.pop, "BW_SYNC_INTERVAL", None)
        for invalid in ("inf", "nan", "0", "-1", "abc"):
            with self.subTest(invalid=invalid):
                os.environ["BW_SYNC_INTERVAL"] = invalid
                self.assertEqual(self._probe_at(2700), 2700)
                with self.assertRaises(operator.kopf.PermanentError):
                    self._probe_at(2701)

    def test_probe_warns_about_an_invalid_limit_only_once(self):
        os.environ["BW_SYNC_STALE_SECONDS"] = "abc"
        self.addCleanup(os.environ.pop, "BW_SYNC_STALE_SECONDS", None)

        for _ in range(3):
            self._probe_at(1)

        warnings = [m for level, m in self.logger.messages if "BW_SYNC_STALE_SECONDS" in m]
        self.assertEqual(len(warnings), 1)

    def test_probe_reports_the_sync_age_while_syncs_succeed(self):
        os.environ["BW_SYNC_INTERVAL"] = "1800"
        self.addCleanup(os.environ.pop, "BW_SYNC_INTERVAL", None)

        self.assertEqual(self._probe_at(1799.6), 1800)

    def test_probe_fails_after_three_intervals_without_a_successful_sync(self):
        # A Ready pod that never syncs (#108: five days of /healthz only)
        # must fail liveness so the kubelet restarts it.
        os.environ["BW_SYNC_INTERVAL"] = "1800"
        self.addCleanup(os.environ.pop, "BW_SYNC_INTERVAL", None)

        self.assertEqual(self._probe_at(5400), 5400)
        with self.assertRaises(operator.kopf.PermanentError):
            self._probe_at(5401)

    def test_probe_limit_can_be_set_and_falls_back_on_invalid_values(self):
        os.environ["BW_SYNC_INTERVAL"] = "100"
        self.addCleanup(os.environ.pop, "BW_SYNC_INTERVAL", None)
        self.addCleanup(os.environ.pop, "BW_SYNC_STALE_SECONDS", None)

        os.environ["BW_SYNC_STALE_SECONDS"] = "1000"
        self.assertEqual(self._probe_at(999), 999)
        with self.assertRaises(operator.kopf.PermanentError):
            self._probe_at(1001)

        for invalid in ("abc", "0", "-5", "inf", "nan"):
            with self.subTest(invalid=invalid):
                os.environ["BW_SYNC_STALE_SECONDS"] = invalid
                with self.assertRaises(operator.kopf.PermanentError):
                    self._probe_at(301)


class ScheduleThreadTests(unittest.TestCase):
    def test_schedule_thread_does_not_keep_the_process_alive(self):
        # A non-daemon thread kept Python running after kopf stopped on SIGTERM,
        # until the kubelet's SIGKILL (#108).
        cease = operator.run_continuously(interval=0.01)
        try:
            [thread] = [
                t for t in threading.enumerate() if type(t).__name__ == "ScheduleThread"
            ]
            self.assertTrue(thread.daemon)
        finally:
            cease.set()


class ScheduledSyncTests(unittest.TestCase):
    """#108 B2: only the scheduled sync feeds the liveness probe. A failed one
    is retried every minute, or three sync intervals hold only two attempts
    (schedule counts from the end of each run) and a 60-minute Vaultwarden
    outage would restart the pod."""

    def setUp(self):
        self.logger = DummyLogger()
        self.addCleanup(setattr, operator, "_scheduled_sync_failed", False)

    def test_a_failed_scheduled_sync_is_retried_until_it_succeeds(self):
        with patch("bitwardenCrdOperator.sync_bw", side_effect=[False, False, True]) as sync:
            operator.safe_sync_bw(self.logger)
            operator.retry_failed_sync(self.logger)
            operator.retry_failed_sync(self.logger)
            operator.retry_failed_sync(self.logger)

        self.assertEqual(3, sync.call_count)

    def test_a_scheduled_sync_that_raises_is_retried(self):
        with patch("bitwardenCrdOperator.sync_bw", side_effect=[RuntimeError("x"), True]) as sync:
            operator.safe_sync_bw(self.logger)
            operator.retry_failed_sync(self.logger)
            operator.retry_failed_sync(self.logger)

        self.assertEqual(2, sync.call_count)

    def test_startup_syncs_once_after_signing_in_and_schedules_the_retry(self):
        calls = MagicMock()
        calls.sync.return_value = True
        with patch.multiple(
            operator,
            bitwarden_signin=calls.signin,
            sync_bw=calls.sync,
            schedule=calls.schedule,
            run_continuously=MagicMock(),
        ):
            operator.load_schedules(self.logger)

        names = [name for name, _, _ in calls.mock_calls if name in ("signin", "sync")]
        self.assertEqual(["signin", "sync"], names)
        calls.schedule.every.assert_any_call(operator.SYNC_RETRY_SECONDS)
        calls.schedule.every.return_value.seconds.do.assert_any_call(
            operator.retry_failed_sync, logger=self.logger
        )


if __name__ == "__main__":
    unittest.main()
