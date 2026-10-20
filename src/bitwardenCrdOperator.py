#!/usr/bin/env python3
import math
import os
import kopf
import schedule
import time
import threading

from utils.utils import (
    _extract_bw_status,
    apikey_login_refusal,
    auth_cooldown_remaining,
    bw_auth_lock,
    command_wrapper,
    normalize_host as _normalize_host,
    parse_configured_server,
    record_auth_failure,
    record_auth_success,
    seconds_since_last_sync,
    sync_bw,
)


AUTH_FAILURE_THRESHOLD = 3
LOGIN_FAILED = "bw login failed"
UNLOCK_FAILED = "Failed to unlock vault"
STALE_SYNC_INTERVALS = 3
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
                command_wrapper(logger, "logout", use_success=False)
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


def _configured_bw_host(logger):
    return parse_configured_server(
        command_wrapper(logger, "config server", use_success=False)
    )


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

        # Log in only when logged out: while a session exists, bw login exits
        # non-zero ("You are already logged in"), which command_wrapper
        # reports as None, so every scheduled relogin counted as a failure.
        status = _bw_status(logger)
        if status is None:
            record_auth_failure()
            return False, "Failed to get bw status"

        if status == "unauthenticated":
            refusal = apikey_login_refusal(logger)
            if refusal is not None:
                record_auth_failure()
                return False, refusal

            login_result = command_wrapper(
                logger, "login --apikey", use_success=False
            )
            if login_result is None or not isinstance(login_result, dict):
                record_auth_failure()
                return False, LOGIN_FAILED

            if login_result.get("success") is False:
                record_auth_failure()
                return False, LOGIN_FAILED

            status = _bw_status(logger)
            if status is None:
                record_auth_failure()
                return False, "Failed to get bw status"

        if status == "unlocked":
            record_auth_success()
            if "DEBUG" in dict(os.environ):
                logger.info("Already unlocked")
            return True, ""

        if status != "locked":
            record_auth_failure()
            return False, f"Unexpected bw status: {status}"

        token_output = command_wrapper(logger, "unlock --passwordenv BW_PASSWORD")
        if token_output is None or not isinstance(token_output, dict):
            record_auth_failure()
            return False, UNLOCK_FAILED

        token = token_output.get("data", {}).get("raw")
        if token is None:
            record_auth_failure()
            return False, "Failed to read session token"

        os.environ["BW_SESSION"] = token
        record_auth_success()
        logger.info("Signin successful. Session exported")
        return True, ""


def _bw_status(logger):
    return _extract_bw_status(command_wrapper(logger, "status", False))


def recover_auth_state(logger, reset_cli_data=False):
    """Logs out. bw logout keeps data.json and with it the device ID; only
    reset_cli_data deletes it, so the next login is a new device (and an email)."""
    os.environ.pop("BW_SESSION", None)
    command_wrapper(logger, "logout", use_success=False)
    if not reset_cli_data:
        return

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
    # Log out keeping data.json (the device ID) first. Delete it (a new device)
    # only when that fails on local CLI state: a refused login (an outage, a
    # rejected key) is not fixed by a reset. The CLI itself empties a file
    # that is not valid JSON (#108).
    for reset_cli_data in (False, True):
        recover_auth_state(logger, reset_cli_data=reset_cli_data)
        # A reset data.json loses the server URL. Without this the recovery
        # login goes to vault.bitwarden.com (Lerentis#133).
        _configure_bw_host(logger)

        recovery_ok, recovery_error = _login_and_unlock(logger, skip_cooldown=True)
        if recovery_ok:
            auth_failures = 0
            logger.info("Authentication recovery succeeded")
            return

        step = "after CLI data reset" if reset_cli_data else "with kept CLI data"
        logger.error(f"Authentication recovery failed ({step}): {recovery_error}")
        if recovery_error == LOGIN_FAILED:
            break

    logger.error("Stopping operator process after failed authentication recovery")
    # Runs in the schedule thread, where sys.exit only ends that thread and
    # leaves the operator up but logged out (Lerentis#134).
    os._exit(1)


DEFAULT_SYNC_INTERVAL_SECONDS = 900.0
_warned_settings = set()


def _positive_seconds(logger, name, default):
    """A finite, positive float from the environment, else the default.
    Warns once per setting: the probe reads it every 10 s."""
    configured = os.environ.get(name)
    if configured is None:
        return default
    try:
        seconds = float(configured)
        if math.isfinite(seconds) and seconds > 0:
            return seconds
    except ValueError:
        pass

    if name not in _warned_settings:
        _warned_settings.add(name)
        logger.warn(f"Invalid {name} '{configured}', using {default:g}")
    return default


def _sync_stale_seconds(logger):
    sync_interval = _positive_seconds(
        logger, "BW_SYNC_INTERVAL", DEFAULT_SYNC_INTERVAL_SECONDS
    )
    return _positive_seconds(
        logger, "BW_SYNC_STALE_SECONDS", STALE_SYNC_INTERVALS * sync_interval
    )


@kopf.on.probe(id="bw_sync")
async def bw_sync_health(logger, **kwargs):
    """Fails /healthz once no bw sync has succeeded for BW_SYNC_STALE_SECONDS
    (default: 3 sync intervals), so the kubelet restarts an operator that is
    alive but no longer syncing (#108: five days of /healthz and nothing else).

    Async on purpose: kopf runs a sync handler in its thread pool, which the
    CR timers fill during every pass, and /healthz would miss the kubelet's
    1 s timeout. Only a PermanentError fails the probe at once; kopf retries
    any other exception every 60 s while /healthz waits, so none escapes."""
    try:
        sync_age = seconds_since_last_sync()
        stale_seconds = _sync_stale_seconds(logger)
    except Exception as exc:
        raise kopf.PermanentError(f"Sync health check failed: {exc}") from exc
    if sync_age > stale_seconds:
        raise kopf.PermanentError(
            f"No successful bw sync for {sync_age:.0f}s (limit {stale_seconds:g}s)"
        )
    return round(sync_age)


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
