#!/usr/bin/env python3
import os
import sys
import kopf
import schedule
import time
import threading

from utils.utils import (
    auth_cooldown_remaining,
    bw_auth_lock,
    command_wrapper,
    record_auth_failure,
    record_auth_success,
    sync_bw,
)


AUTH_FAILURE_THRESHOLD = 3
auth_failures = 0


def _configure_bw_host(logger):
    if "BW_HOST" in os.environ:
        try:
            home_dir = os.path.expanduser("~")
            bw_host_file = os.path.join(home_dir, ".bw_host")
            bw_host_env = _normalize_host(os.getenv("BW_HOST"))
            if bw_host_env is None:
                return

            saved_host = None
            if os.path.isfile(bw_host_file):
                with open(bw_host_file, "r") as f:
                    saved_host = _normalize_host(f.read().strip())

            configured_host = _configured_bw_host(logger)
            needs_config_set = configured_host != bw_host_env or (
                saved_host is not None
                and configured_host is not None
                and saved_host != configured_host
            )

            if needs_config_set:
                command_wrapper(
                    logger, f"config server {bw_host_env}", use_success=False
                )
                configured_host = _configured_bw_host(logger)

            if configured_host != bw_host_env:
                logger.warn(
                    f"Failed to configure Bitwarden server. expected={bw_host_env}, actual={configured_host}"
                )
                return

            if saved_host != bw_host_env:
                with open(bw_host_file, "w") as f:
                    f.write(bw_host_env)

            if "DEBUG" in dict(os.environ):
                logger.info("Bitwarden server configuration verified")
        except BaseException:
            logger.warn("Received non-zero exit code from server config")
            logger.warn("This is expected from startup")
    else:
        logger.info("BW_HOST not set. Assuming SaaS installation")


def _normalize_host(host):
    if host is None:
        return None
    return host.strip().rstrip("/")


def _configured_bw_host(logger):
    config_output = command_wrapper(logger, "config server", use_success=False)
    if not isinstance(config_output, dict):
        return None

    data = config_output.get("data", {})
    template_value = data.get("template")

    if isinstance(template_value, str):
        return _normalize_host(template_value)

    if isinstance(template_value, dict):
        for key in ("server", "url", "value"):
            if key in template_value:
                return _normalize_host(template_value.get(key))

    raw_value = data.get("raw")
    if isinstance(raw_value, str):
        return _normalize_host(raw_value)

    return None


def _auth_failure_threshold(logger):
    configured_threshold = os.environ.get(
        "BW_AUTH_FAILURE_THRESHOLD", str(AUTH_FAILURE_THRESHOLD)
    )
    normalized_threshold = configured_threshold.strip()
    if normalized_threshold.isdecimal():
        threshold = int(normalized_threshold)
        if threshold > 0:
            return threshold

    logger.warn(
        f"Invalid BW_AUTH_FAILURE_THRESHOLD '{configured_threshold}', using {AUTH_FAILURE_THRESHOLD}"
    )
    return AUTH_FAILURE_THRESHOLD


def _login_and_unlock(logger, skip_cooldown=False):
    with bw_auth_lock:
        cooldown_remaining = auth_cooldown_remaining(logger)
        if not skip_cooldown and cooldown_remaining > 0:
            return (
                False,
                f"Authentication cooldown active for {cooldown_remaining:.1f}s",
            )

        login_result = command_wrapper(logger, "login --apikey", use_success=False)
        if login_result is None or not isinstance(login_result, dict):
            record_auth_failure()
            return False, "bw login failed"

        login_success = login_result.get("success")
        if login_success is False and not _is_already_logged_in(login_result):
            record_auth_failure()
            return False, "bw login failed"

        status_output = command_wrapper(logger, "status", False)
        if status_output is None or not isinstance(status_output, dict):
            record_auth_failure()
            return False, "Failed to get bw status"

        status = status_output.get("data", {}).get("template", {}).get("status")
        if status == "unlocked":
            record_auth_success()
            if "DEBUG" in dict(os.environ):
                logger.info("Already unlocked")
            return True, ""

        token_output = command_wrapper(logger, "unlock --passwordenv BW_PASSWORD")
        if token_output is None or not isinstance(token_output, dict):
            record_auth_failure()
            return False, "Failed to unlock vault"

        token = token_output.get("data", {}).get("raw")
        if token is None:
            record_auth_failure()
            return False, "Failed to read session token"

        os.environ["BW_SESSION"] = token
        record_auth_success()
        logger.info("Signin successful. Session exported")
        return True, ""


def _is_already_logged_in(login_result):
    data = (
        login_result.get("data", {})
        if isinstance(login_result.get("data"), dict)
        else {}
    )
    messages = [
        login_result.get("message"),
        login_result.get("error"),
        login_result.get("errorMessage"),
        data.get("message"),
        data.get("error"),
    ]

    for message in messages:
        if isinstance(message, str) and "already logged in" in message.lower():
            return True

    return False


def recover_auth_state(logger):
    os.environ.pop("BW_SESSION", None)
    command_wrapper(logger, "logout", use_success=False)

    home_dir = os.path.expanduser("~")
    cli_data_file = os.path.join(home_dir, ".config", "Bitwarden CLI", "data.json")
    if os.path.isfile(cli_data_file):
        try:
            os.remove(cli_data_file)
            logger.warn("Removed Bitwarden CLI cache file to recover auth state")
        except OSError as exc:
            logger.warn(f"Could not remove Bitwarden CLI cache file: {exc}")


def bitwarden_signin(logger, **kwargs):
    global auth_failures

    _configure_bw_host(logger)
    failure_threshold = _auth_failure_threshold(logger)

    signin_ok, signin_error = _login_and_unlock(logger)
    if signin_ok:
        if auth_failures > 0:
            logger.info("Authentication recovered")
        auth_failures = 0
        return

    auth_failures += 1
    logger.error(
        f"Authentication failed ({auth_failures}/{failure_threshold}): {signin_error}"
    )

    if auth_failures < failure_threshold:
        return

    logger.warn(
        "Authentication failure threshold reached, recovering Bitwarden auth state"
    )
    recover_auth_state(logger)

    recovery_ok, recovery_error = _login_and_unlock(logger, skip_cooldown=True)
    if recovery_ok:
        auth_failures = 0
        logger.info("Authentication recovery succeeded")
        return

    logger.error(f"Authentication recovery failed: {recovery_error}")
    logger.error("Stopping operator process after failed authentication recovery")
    sys.exit(1)


def run_continuously(interval=30):
    cease_continuous_run = threading.Event()

    class ScheduleThread(threading.Thread):
        @classmethod
        def run(self):
            while not cease_continuous_run.is_set():
                schedule.run_pending()
                time.sleep(interval)

    continuous_thread = ScheduleThread()
    continuous_thread.start()
    return cease_continuous_run


def safe_bitwarden_signin(logger, **kwargs):
    """Wrapper for bitwarden_signin that prevents schedule job cancellation on errors."""
    try:
        bitwarden_signin(logger, **kwargs)
    except Exception as e:
        logger.error(f"Relogin failed: {e}. Will retry on next schedule.")


def safe_sync_bw(logger, **kwargs):
    """Wrapper for sync_bw that prevents schedule job cancellation on errors."""
    try:
        sync_bw(logger, **kwargs)
    except Exception as e:
        logger.error(f"Sync failed: {e}. Will retry on next schedule.")


@kopf.on.startup()
def load_schedules(logger, **kwargs):
    logger.info("Loading schedules")
    bitwarden_signin(logger)

    bw_sync_interval = float(os.environ.get("BW_SYNC_INTERVAL", 900))
    bw_relogin_interval = float(os.environ.get("BW_RELOGIN_INTERVAL", 3600))

    schedule.every(bw_relogin_interval).seconds.do(safe_bitwarden_signin, logger=logger)
    schedule.every(bw_sync_interval).seconds.do(safe_sync_bw, logger=logger)
    run_continuously()
