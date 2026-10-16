import os
import shutil
import signal
import tempfile
import subprocess
import sys
import threading
import time
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
        os.environ.pop("BW_COMMAND_TIMEOUT", None)
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

    @patch("utils.utils.subprocess.Popen")
    def test_command_wrapper_never_runs_two_bw_processes_at_once(self, popen_mock):
        # Parallel bw processes rewrite data.json concurrently and corrupt it
        # ("Malformed JSON in file"), which logs the CLI out.
        state = {"running": 0, "max": 0}
        state_lock = threading.Lock()

        def make_process(*args, **kwargs):
            process = MagicMock()
            process.returncode = 0

            def communicate(*a, **kw):
                with state_lock:
                    state["running"] += 1
                    state["max"] = max(state["max"], state["running"])
                time.sleep(0.05)
                with state_lock:
                    state["running"] -= 1
                return (b'{"success": true}', b"")

            process.communicate.side_effect = communicate
            return process

        popen_mock.side_effect = make_process
        threads = [
            threading.Thread(target=utils.command_wrapper, args=(self.logger, "sync"))
            for _ in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(popen_mock.call_count, 4)
        self.assertEqual(state["max"], 1)

    @patch("utils.utils.os.killpg")
    @patch("utils.utils.subprocess.Popen")
    def test_command_wrapper_kills_a_hung_bw_call_and_fails_it(
        self, popen_mock, killpg_mock
    ):
        # A hung bw process would otherwise hold the command lock forever.
        os.environ["BW_COMMAND_TIMEOUT"] = "5"
        self.addCleanup(os.environ.pop, "BW_COMMAND_TIMEOUT", None)
        process = MagicMock()
        process.pid = 4242
        process.returncode = -9
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd="bw", timeout=5),
            (b"", b""),
        ]
        popen_mock.return_value = process

        result = utils.command_wrapper(self.logger, "sync")

        self.assertIsNone(result)
        self.assertTrue(popen_mock.call_args.kwargs["start_new_session"])
        self.assertEqual(process.communicate.call_args_list[0].kwargs, {"timeout": 5.0})
        killpg_mock.assert_called_once_with(4242, signal.SIGKILL)
        self.assertTrue(
            any("timed out after 5" in message for _, message in self.logger.messages)
        )

    @patch("utils.utils.subprocess.Popen")
    def test_command_wrapper_default_timeout_is_120_seconds(self, popen_mock):
        process = MagicMock()
        process.returncode = 0
        process.communicate.return_value = (b'{"success": true}', b"")
        popen_mock.return_value = process

        utils.command_wrapper(self.logger, "status")

        self.assertEqual(process.communicate.call_args.kwargs, {"timeout": 120.0})

    @patch("utils.utils.subprocess.Popen")
    def test_command_wrapper_uses_the_environment_current_when_it_runs(
        self, popen_mock
    ):
        # A call queued behind the lock must not reuse a session that was
        # replaced while it waited.
        process = MagicMock()
        process.returncode = 0
        process.communicate.return_value = (b'{"success": true}', b"")
        popen_mock.return_value = process
        os.environ["BW_SESSION"] = "old-session"

        utils.bw_command_lock.acquire()
        waiting = threading.Thread(
            target=utils.command_wrapper, args=(self.logger, "sync")
        )
        waiting.start()
        time.sleep(0.05)
        os.environ["BW_SESSION"] = "new-session"
        utils.bw_command_lock.release()
        waiting.join()

        self.assertEqual(popen_mock.call_args.kwargs["env"]["BW_SESSION"], "new-session")

    def test_command_timeout_rejects_non_finite_and_caps_large_values(self):
        for configured, expected in (("inf", 120.0), ("nan", 120.0), ("-1", 120.0),
                                     ("abc", 120.0), ("99999", 3600.0), ("30", 30.0)):
            os.environ["BW_COMMAND_TIMEOUT"] = configured
            self.assertEqual(utils._command_timeout_seconds(self.logger), expected, configured)

    @patch("utils.utils.os.killpg")
    @patch("utils.utils.subprocess.Popen")
    def test_command_wrapper_kills_the_process_on_an_unexpected_error(
        self, popen_mock, killpg_mock
    ):
        process = MagicMock()
        process.pid = 4243
        process.communicate.side_effect = [OverflowError("boom"), (b"", b"")]
        popen_mock.return_value = process

        with self.assertRaises(OverflowError):
            utils.command_wrapper(self.logger, "sync")

        killpg_mock.assert_called_once_with(4243, signal.SIGKILL)
        self.assertFalse(utils.bw_command_lock.locked())

    def test_command_wrapper_really_kills_a_hung_bw_and_frees_the_lock(self):
        # Real processes: a fake bw that starts a sleeping child in its group.
        bin_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, bin_dir)
        pid_file = os.path.join(bin_dir, "child.pid")
        fake_bw = os.path.join(bin_dir, "bw")
        with open(fake_bw, "w") as f:
            f.write(
                "#!/bin/sh\n"
                'if [ "$2" = "status" ]; then echo \'{"success": true}\'; exit 0; fi\n'
                f"sleep 30 & echo $! > {pid_file}\n"
                "wait\n"
            )
        os.chmod(fake_bw, 0o755)
        original_path = os.environ["PATH"]
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        self.addCleanup(os.environ.__setitem__, "PATH", original_path)
        os.environ["BW_COMMAND_TIMEOUT"] = "0.5"

        started = time.monotonic()
        result = utils.command_wrapper(self.logger, "sync")
        elapsed = time.monotonic() - started

        self.assertIsNone(result)
        self.assertLess(elapsed, 5)
        with open(pid_file) as f:
            child_pid = int(f.read())
        time.sleep(0.1)
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)
        self.assertEqual(utils.command_wrapper(self.logger, "status"), {"success": True})

    def _ok_process(self, popen_mock):
        process = MagicMock()
        process.returncode = 0
        process.communicate.return_value = (b'{"success": true}', b"")
        popen_mock.return_value = process

    @patch("utils.utils.subprocess.Popen")
    def test_command_wrapper_runs_bw_without_a_shell(self, popen_mock):
        self._ok_process(popen_mock)

        utils.command_wrapper(self.logger, "unlock --passwordenv BW_PASSWORD")

        self.assertEqual(
            popen_mock.call_args.args[0],
            ["bw", "--response", "unlock", "--passwordenv", "BW_PASSWORD"],
        )
        self.assertFalse(popen_mock.call_args.kwargs.get("shell", False))

    @patch("utils.utils.subprocess.Popen")
    def test_item_id_from_a_cr_cannot_inject_shell_commands(self, popen_mock):
        self._ok_process(popen_mock)
        hostile = "abc; touch /tmp/pwned $(id)"

        utils.get_secret_from_bitwarden(self.logger, hostile)

        argv = popen_mock.call_args_list[-1].args[0]
        self.assertEqual(argv, ["bw", "--response", "get", "item", hostile])
        self.assertFalse(popen_mock.call_args.kwargs.get("shell", False))

    @patch("utils.utils.subprocess.Popen")
    def test_attachment_name_and_item_id_are_single_arguments(self, popen_mock):
        self._ok_process(popen_mock)

        utils.get_attachment(self.logger, "item-1", "my file; rm -rf /")

        self.assertEqual(
            popen_mock.call_args.args[0],
            ["bw", "--raw", "get", "attachment", "my file; rm -rf /", "--itemid", "item-1"],
        )

    @patch("utils.utils.subprocess.Popen")
    def test_non_string_cr_values_become_string_arguments(self, popen_mock):
        self._ok_process(popen_mock)

        utils.get_secret_from_bitwarden(self.logger, 123)
        self.assertEqual(popen_mock.call_args.args[0][-1], "123")

        utils.get_attachment(self.logger, 456, 789)
        self.assertEqual(popen_mock.call_args.args[0][-4:], ["attachment", "789", "--itemid", "456"])

    @patch("utils.utils.subprocess.Popen")
    def test_cr_values_that_look_like_options_are_rejected(self, popen_mock):
        self._ok_process(popen_mock)

        self.assertIsNone(utils.get_secret_from_bitwarden(self.logger, "--session=x"))
        self.assertIsNone(utils.get_attachment(self.logger, "item-1", "-x"))
        self.assertIsNone(utils.get_attachment(self.logger, "--help", "file"))

        commands = [call.args[0] for call in popen_mock.call_args_list]
        self.assertFalse(any(argv[2] == "get" for argv in commands), commands)

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
