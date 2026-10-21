import os
import json
import math
import re
import shlex
import signal
import subprocess
import threading
import time
import kubernetes
import kopf

bw_sync_interval = float(os.environ.get("BW_SYNC_INTERVAL", 900))

DEFAULT_AUTH_COOLDOWN_SECONDS = 30.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 120.0
MAX_COMMAND_TIMEOUT_SECONDS = 3600.0
KILL_REAP_TIMEOUT_SECONDS = 5.0
bw_auth_lock = threading.Lock()
# Every bw process reads and rewrites data.json; two at once corrupt it
# ("Malformed JSON in file"), which logs the CLI out. Run them one by one.
bw_command_lock = threading.Lock()
_last_auth_failure_at = 0.0
# Starts at import, so a new pod gets the full grace period before its
# first sync. The liveness probe reads it (bitwardenCrdOperator.py).
_last_sync_success_at = time.monotonic()
# Whether the latest bw sync of any kind succeeded: a failed one leaves a stale
# cache. bw login runs a full sync, so it starts true.
_last_sync_succeeded = True


class BitwardenCommandException(Exception):
    pass


class BitwardenItemNotFound(BitwardenCommandException):
    pass


# Retry delay for a failed item lookup that is not a missing item (a timeout,
# a logged-out CLI): the same as kopf's default backoff.
LOOKUP_RETRY_SECONDS = 60


def _str_to_bool(value):
    normalized_value = str(value).strip().lower()
    return normalized_value in ("1", "true", "t", "yes", "y", "on")


def _rejects_option_like(logger, **values):
    """CR fields become bw arguments; one starting with '-' could pass for
    an option, so refuse it."""
    for field, value in values.items():
        if str(value).startswith("-"):
            logger.warn(f"Refusing {field} that starts with '-': {value!r}")
            return True
    return False


# bw's own GUID test (Utils.guidRegex, CLI 2025.5.0), lowercase only. Any
# other id makes bw get item search item names, so a renamed or duplicate
# item could sync the wrong secret (#108).
ITEM_ID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def _rejects_non_uuid(logger, id):
    if ITEM_ID_PATTERN.fullmatch(id):
        return False
    logger.warn(f"Refusing Bitwarden item id {id!r}: not a lowercase UUID")
    return True


def get_secret_from_bitwarden(logger, id):
    """Returns the item, or raises kopf.TemporaryError, which kopf logs as one
    line and retries after its delay. A missing item (deleted, or not shared
    with the operator) waits a sync interval; it used to crash the handlers
    on None and retry every 60 s (Geekvetica#108 B5). Temporary, never
    permanent, so a create handler still picks up a corrected spec.id.

    Reads the local cache: the scheduled sync refreshes it once per cycle and
    change handlers sync before their lookups (#108 B2). BW_FORCE_SYNC=true
    syncs before every lookup, as before."""
    id = str(id)
    if _rejects_non_uuid(logger, id):
        raise kopf.TemporaryError(
            f"Refusing Bitwarden item id {id!r}: not a lowercase UUID; fix the CR",
            delay=bw_sync_interval,
        )
    if _str_to_bool(os.environ.get("BW_FORCE_SYNC", "false")):
        if "DEBUG" in dict(os.environ):
            logger.info("Running with global force sync")
        sync_bw(logger, record_health=False)
    try:
        item = command_wrapper(logger, command=["get", "item", id], raise_not_found=True)
    except BitwardenItemNotFound:
        if not _last_sync_succeeded:
            # A stale cache answers "Not found." too: retry soon.
            raise kopf.TemporaryError(
                f"Bitwarden item {id} not found after a failed sync; "
                f"retrying in {LOOKUP_RETRY_SECONDS}s",
                delay=LOOKUP_RETRY_SECONDS,
            ) from None
        raise kopf.TemporaryError(
            f"Bitwarden item {id} not found (deleted, or not shared with the "
            f"operator); retrying in {bw_sync_interval:g}s",
            delay=bw_sync_interval,
        ) from None
    if item is None:
        raise kopf.TemporaryError(
            f"Lookup of Bitwarden item {id} failed; retrying in {LOOKUP_RETRY_SECONDS}s",
            delay=LOOKUP_RETRY_SECONDS,
        )
    return item


def sync_bw(logger, record_health=True):
    """Returns whether the vault sync succeeded. Only the scheduled sync
    records health: a CR change must not hide a dead schedule thread from
    the liveness probe."""
    global _last_sync_succeeded
    _last_sync_succeeded = command_wrapper(logger, command="sync") is not None
    if not _last_sync_succeeded:
        logger.info("bw sync failed")
        return False
    if record_health:
        record_sync_success()
    return True


def record_sync_success():
    global _last_sync_success_at
    _last_sync_success_at = time.monotonic()


def seconds_since_last_sync():
    return time.monotonic() - _last_sync_success_at


def get_attachment(logger, id, name):
    id, name = str(id), str(name)
    if _rejects_non_uuid(logger, id) or _rejects_option_like(logger, name=name):
        return None
    return command_wrapper(
        logger, command=["get", "attachment", name, "--itemid", id], raw=True
    )


def unlock_bw(logger):
    with bw_auth_lock:
        cooldown_remaining = auth_cooldown_remaining(logger)
        if cooldown_remaining > 0:
            raise BitwardenCommandException(
                f"Authentication cooldown active for {cooldown_remaining:.1f}s"
            )

        status_output = command_wrapper(logger, "status", False)
        if status_output is None:
            record_auth_failure()
            raise BitwardenCommandException("Failed to get bw status")

        status = _extract_bw_status(status_output)
        if status is None:
            record_auth_failure()
            raise BitwardenCommandException("Failed to parse bw status")

        if status == "unlocked":
            record_auth_success()
            if "DEBUG" in dict(os.environ):
                logger.info("Already unlocked")
            return

        if status == "unauthenticated":
            refusal = apikey_login_refusal(logger)
            if refusal is not None:
                record_auth_failure()
                raise BitwardenCommandException(refusal)

            login_result = command_wrapper(logger, "login --apikey", use_success=False)
            if login_result is None or not isinstance(login_result, dict):
                record_auth_failure()
                raise BitwardenCommandException("bw login failed")

            login_success = login_result.get("success")
            if login_success is False and not _is_already_logged_in(login_result):
                record_auth_failure()
                raise BitwardenCommandException("bw login failed")

            status_output = command_wrapper(logger, "status", False)
            if status_output is None:
                record_auth_failure()
                raise BitwardenCommandException("Failed to get bw status")

            status = _extract_bw_status(status_output)
            if status is None:
                record_auth_failure()
                raise BitwardenCommandException("Failed to parse bw status")

            if status == "unlocked":
                record_auth_success()
                if "DEBUG" in dict(os.environ):
                    logger.info("Already unlocked")
                return

        if status != "locked":
            record_auth_failure()
            raise BitwardenCommandException(f"Unexpected bw status: {status}")

        token_output = command_wrapper(logger, "unlock --passwordenv BW_PASSWORD")
        if token_output is None:
            record_auth_failure()
            raise BitwardenCommandException("Failed to unlock vault")

        token = token_output.get("data", {}).get("raw")
        if token is None:
            record_auth_failure()
            raise BitwardenCommandException("Failed to read session token")

        os.environ["BW_SESSION"] = token
        record_auth_success()
        logger.info("Signin successful. Session exported")


def _extract_bw_status(status_output):
    if not isinstance(status_output, dict):
        return None

    data = status_output.get("data")
    if not isinstance(data, dict):
        return None

    template = data.get("template")
    if not isinstance(template, dict):
        return None

    status = template.get("status")
    if isinstance(status, str):
        return status

    return None


def normalize_host(host):
    if not isinstance(host, str):
        return None
    return host.strip().rstrip("/")


def parse_configured_server(config_output):
    """The server URL from `bw config server` output, or None. Never raises:
    a malformed response must refuse the API-key login, not escape it."""
    if not isinstance(config_output, dict):
        return None

    data = config_output.get("data")
    if not isinstance(data, dict):
        return None
    template_value = data.get("template")

    if isinstance(template_value, str):
        return normalize_host(template_value)

    if isinstance(template_value, dict):
        for key in ("server", "url", "value"):
            if key in template_value:
                return normalize_host(template_value.get(key))

    data_value = data.get("data")
    if isinstance(data_value, str):
        return normalize_host(data_value)

    raw_value = data.get("raw")
    if isinstance(raw_value, str):
        return normalize_host(raw_value)

    return None


def apikey_login_refusal(logger):
    """Why the API key must not be sent now, or None. With BW_HOST set the
    key goes only to that server: a reset data.json points the CLI at
    bitwarden.com (Lerentis#133). Without BW_HOST the operator targets the
    SaaS and there is nothing to check."""
    expected = normalize_host(os.environ.get("BW_HOST"))
    if not expected:
        return None

    configured = parse_configured_server(
        command_wrapper(logger, "config server", use_success=False)
    )
    if configured == expected:
        return None

    message = (
        f"Refusing API-key login: bw server is {configured!r}, "
        f"BW_HOST is {expected!r}"
    )
    logger.warn(message)
    return message


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


def should_skip_due_to_auth_cooldown(exc):
    return isinstance(exc, BitwardenCommandException) and str(exc).startswith(
        "Authentication cooldown active"
    )


def _kill_and_reap(logger, sp):
    """Kill bw's whole process group and collect its output. Never raises,
    so neither a timeout nor the error that led here gets replaced."""
    try:
        os.killpg(sp.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        return sp.communicate(timeout=KILL_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # A descendant outside the group still holds a pipe: give up on it.
        for pipe in (sp.stdout, sp.stderr):
            if pipe:
                pipe.close()
        try:
            sp.wait(timeout=KILL_REAP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            logger.warn(f"bw process {sp.pid} did not exit after SIGKILL")
        return b"", b""


def command_wrapper(
    logger, command, use_success: bool = True, raw: bool = False, raise_not_found: bool = False
):
    """Run one bw command. `command` is a fixed string such as "sync", or a
    list when it carries values from a CR, which then stay single arguments.
    No shell is involved. With raise_not_found, a "Not found." response
    raises BitwardenItemNotFound instead of logging and returning None."""
    response_flag = "--raw" if raw else "--response"
    args = shlex.split(command) if isinstance(command, str) else list(command)
    argv = ["bw", response_flag, *args]
    command_line = " ".join(argv)
    timeout = _command_timeout_seconds(logger)
    with bw_command_lock:
        # Read the environment only once it is this call's turn: BW_SESSION
        # may have been replaced while it waited.
        system_env = dict(os.environ)
        try:
            sp = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=system_env,
                start_new_session=True,
            )
        except OSError as exc:
            logger.warn(f"bw could not start ({exc}): {command_line}")
            return None
        try:
            out, err = sp.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_and_reap(logger, sp)
            logger.warn(
                f"bw command timed out after {timeout:g}s and was killed: "
                f"{command_line}"
            )
            return None
        except BaseException:
            # Never leave a bw process running once the lock is released.
            _kill_and_reap(logger, sp)
            raise

    stdout = (
        out.decode(encoding="UTF-8", errors="replace")
        if isinstance(out, bytes)
        else str(out)
    )
    stderr = (
        err.decode(encoding="UTF-8", errors="replace")
        if isinstance(err, bytes)
        else str(err)
    )

    if sp.returncode != 0:
        if raise_not_found and _is_not_found_response(stdout):
            raise BitwardenItemNotFound(command_line)
        logger.warn(
            f"bw command failed (returncode={sp.returncode}): {command_line}"
        )
        if stderr.strip():
            logger.warn(f"bw stderr: {stderr.strip()}")
        if stdout.strip():
            logger.warn(f"bw stdout: {stdout.strip()}")
        return None

    if stderr.strip():
        logger.warn(f"bw stderr (returncode=0): {stderr.strip()}")

    if raw:
        return stdout

    if "DEBUG" in system_env:
        logger.info(stdout)

    try:
        resp = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warn(
            f"bw command returned non-JSON output: {command_line}"
        )
        if stdout.strip():
            logger.warn(f"bw stdout: {stdout.strip()}")
        return None

    success = resp.get("success") if isinstance(resp, dict) else None
    if success is not None and (not use_success or (use_success and success is True)):
        return resp

    logger.warn(resp)
    return None


def _is_not_found_response(stdout):
    try:
        resp = json.loads(stdout)
    except json.JSONDecodeError:
        return False
    return isinstance(resp, dict) and resp.get("message") == "Not found."


def _command_timeout_seconds(logger):
    configured_timeout = os.environ.get(
        "BW_COMMAND_TIMEOUT", str(DEFAULT_COMMAND_TIMEOUT_SECONDS)
    )
    try:
        timeout_seconds = float(configured_timeout)
        if math.isfinite(timeout_seconds) and timeout_seconds > 0:
            return min(timeout_seconds, MAX_COMMAND_TIMEOUT_SECONDS)
    except ValueError:
        pass

    logger.warn(
        f"Invalid BW_COMMAND_TIMEOUT '{configured_timeout}', using {DEFAULT_COMMAND_TIMEOUT_SECONDS}"
    )
    return DEFAULT_COMMAND_TIMEOUT_SECONDS


def _auth_cooldown_seconds(logger):
    configured_cooldown = os.environ.get(
        "BW_AUTH_COOLDOWN_SECONDS", str(DEFAULT_AUTH_COOLDOWN_SECONDS)
    )
    try:
        cooldown_seconds = float(configured_cooldown)
        if cooldown_seconds >= 0:
            return cooldown_seconds
    except ValueError:
        pass

    logger.warn(
        f"Invalid BW_AUTH_COOLDOWN_SECONDS '{configured_cooldown}', using {DEFAULT_AUTH_COOLDOWN_SECONDS}"
    )
    return DEFAULT_AUTH_COOLDOWN_SECONDS


def auth_cooldown_remaining(logger):
    if _last_auth_failure_at == 0.0:
        return 0.0

    cooldown_seconds = _auth_cooldown_seconds(logger)
    elapsed = time.monotonic() - _last_auth_failure_at
    if elapsed >= cooldown_seconds:
        return 0.0

    return cooldown_seconds - elapsed


def record_auth_failure():
    global _last_auth_failure_at
    _last_auth_failure_at = time.monotonic()


def record_auth_success():
    global _last_auth_failure_at
    _last_auth_failure_at = 0.0


def parse_login_scope(secret_json, key):
    return secret_json["data"]["login"][key]


def parse_fields_scope(secret_json, key):
    if "fields" not in secret_json["data"]:
        return None
    for entry in secret_json["data"]["fields"]:
        if entry["name"] == key:
            return entry["value"]


# Common secret management functions
def build_secret_metadata(
    secret_name, managed_type, namespace, name, custom_annotations=None, labels=None
):
    """Build common secret metadata with annotations and labels."""
    annotations = {"managed": managed_type, "managedObject": f"{namespace}/{name}"}

    if custom_annotations:
        annotations.update(custom_annotations)

    if not labels:
        labels = {}

    return kubernetes.client.V1ObjectMeta(
        name=secret_name, annotations=annotations, labels=labels
    )


def extract_secret_config(spec):
    """Extract common secret configuration from spec."""
    return {
        "secret_name": spec.get("name"),
        "secret_namespace": spec.get("namespace"),
        "labels": spec.get("labels"),
        "custom_annotations": spec.get("annotations"),
        "custom_secret_type": spec.get("secretType", "Opaque"),
    }


def parse_old_config(body):
    """Parse old configuration from body annotations."""
    if "kopf.zalando.org/last-handled-configuration" not in body.metadata.annotations:
        return None, None, None, None

    old_config = json.loads(
        body.metadata.annotations["kopf.zalando.org/last-handled-configuration"]
    )
    old_secret_name = old_config["spec"].get("name")
    old_secret_namespace = old_config["spec"].get("namespace")
    old_secret_type = old_config["spec"].get("secretType", "Opaque")

    return old_config, old_secret_name, old_secret_namespace, old_secret_type


def should_recreate_secret(
    old_secret_name,
    secret_name,
    old_secret_namespace,
    secret_namespace,
    old_secret_type,
    secret_type,
):
    """Determine if secret should be recreated due to name/namespace/type change."""
    return (
        old_secret_name != secret_name
        or old_secret_namespace != secret_namespace
        or old_secret_type != secret_type
    )


def apply_owner_reference(secret, secret_namespace, namespace):
    """Apply owner reference if secret is in same namespace."""
    if secret_namespace == namespace:
        kopf.append_owner_reference(secret)


def delete_secret(logger, secret_name, secret_namespace):
    """Delete a Kubernetes secret."""
    api = kubernetes.client.CoreV1Api()

    try:
        api.delete_namespaced_secret(secret_name, secret_namespace)
        logger.info(f"Secret {secret_namespace}/{secret_name} has been deleted")
    except BaseException:
        logger.warn(f"Could not delete secret {secret_namespace}/{secret_name}!")


def create_secret(logger, secret, secret_namespace):
    """Create a Kubernetes secret."""
    api = kubernetes.client.CoreV1Api()
    api.create_namespaced_secret(namespace=secret_namespace, body=secret)
    logger.info(f"Secret {secret_namespace}/{secret.metadata.name} has been created")


def update_secret(logger, secret, secret_namespace):
    """Update a Kubernetes secret."""
    api = kubernetes.client.CoreV1Api()

    try:
        api.replace_namespaced_secret(
            name=secret.metadata.name, body=secret, namespace=secret_namespace
        )
        logger.info(
            f"Secret {secret_namespace}/{secret.metadata.name} has been updated"
        )
    except BaseException as e:
        logger.warn(
            f"Could not update secret {secret_namespace}/{secret.metadata.name}!"
        )
        logger.warn(f"Exception: {e}")
