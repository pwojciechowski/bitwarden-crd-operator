import kopf
import base64
import kubernetes
import sys
import time

from utils.utils import (
    BitwardenCommandException,
    unlock_bw,
    bw_sync_interval,
    build_secret_metadata,
    extract_secret_config,
    parse_old_config,
    should_recreate_secret,
    apply_owner_reference,
    should_skip_due_to_auth_cooldown,
    delete_secret,
    create_secret,
    update_secret,
)
from lookups.bitwarden_lookup import BitwardenLookupHandler
from jinja2 import BaseLoader
from jinja2.sandbox import ImmutableSandboxedEnvironment


# Limits for a broken or hostile CR (#108). The real templates are at most
# 285 characters and render to at most 109 (2026-10-21). Single operations
# that allocate a lot (a huge "x" * n, center, ~ chains) stay bounded only by
# the pod's memory limit.
TEMPLATE_MAX_CHARS = 16 * 1024
RENDERED_MAX_CHARS = 256 * 1024
# CPU time of the rendering thread: waiting for bw lookups does not count.
RENDER_CPU_SECONDS = 5.0


class _RenderCpuBudgetExceeded(BaseException):
    """A BaseException, so no except Exception on the way swallows it."""


def _cpu_budget_tracer(deadline):
    def tracer(frame, event, arg):
        if time.thread_time() > deadline:
            raise _RenderCpuBudgetExceeded()
        return tracer

    return tracer


def _refuse(message):
    # Only a CR change fixes it: retry at the sync interval, not every 60 s.
    return kopf.TemporaryError(f"Refusing template: {message}", delay=bw_sync_interval)


def render_template(logger, template):
    if len(template) > TEMPLATE_MAX_CHARS:
        raise _refuse(f"template is {len(template)} characters (limit {TEMPLATE_MAX_CHARS})")

    # Templates come from CRs; sandboxed so they cannot reach Python internals
    # (and through them the operator's environment and credentials).
    jinja_template = ImmutableSandboxedEnvironment(loader=BaseLoader()).from_string(
        template
    )
    jinja_template.globals.update(
        {
            "bitwarden_lookup": BitwardenLookupHandler(logger).bitwarden_lookup,
        }
    )

    chunks, size = [], 0
    previous_tracer = sys.gettrace()
    sys.settrace(_cpu_budget_tracer(time.thread_time() + RENDER_CPU_SECONDS))
    try:
        # Streamed, so a loop that writes output stops at the limit.
        for chunk in jinja_template.generate():
            size += len(chunk)
            if size > RENDERED_MAX_CHARS:
                raise _refuse(f"rendered output exceeds {RENDERED_MAX_CHARS} characters")
            chunks.append(chunk)
    except _RenderCpuBudgetExceeded:
        raise _refuse(f"rendering used more than {RENDER_CPU_SECONDS:g}s of CPU") from None
    finally:
        sys.settrace(previous_tracer)
    return "".join(chunks)


def create_template_secret(logger, secret, filename, template):
    secret.data = {}
    secret.data[filename] = str(
        base64.b64encode(render_template(logger, template).encode("utf-8")), "utf-8"
    )
    return secret


def create_template_obj(logger, secret, content_def):
    secret.data = {}
    for eleml in content_def:
        for k, elem in eleml.items():
            for key, value in elem.items():
                if key == "filename":
                    _file_name = value
                if key == "template":
                    _template = value
            secret.data[_file_name] = str(
                base64.b64encode(render_template(logger, _template).encode("utf-8")),
                "utf-8",
            )
    return secret


@kopf.on.create("bitwarden-template.lerentis.uploadfilter24.eu")
def create_managed_secret(spec, name, namespace, logger, body, **kwargs):
    template = spec.get("template")
    if template is not None:
        create_beta7_secret(spec, name, namespace, logger, body, **kwargs)
        return

    content_def = spec.get("content")
    config = extract_secret_config(spec)

    unlock_bw(logger)

    secret = kubernetes.client.V1Secret()
    secret.metadata = build_secret_metadata(
        config["secret_name"],
        "bitwarden-template.lerentis.uploadfilter24.eu",
        namespace,
        name,
        config["custom_annotations"],
        config["labels"],
    )
    secret.type = config["custom_secret_type"]
    secret = create_template_obj(logger, secret, content_def)

    apply_owner_reference(secret, config["secret_namespace"], namespace)
    create_secret(logger, secret, config["secret_namespace"])


def create_beta7_secret(spec, name, namespace, logger, body, **kwargs):
    template = spec.get("template")
    filename = spec.get("filename")
    config = extract_secret_config(spec)

    unlock_bw(logger)

    secret = kubernetes.client.V1Secret()
    secret.metadata = build_secret_metadata(
        config["secret_name"],
        "bitwarden-template.lerentis.uploadfilter24.eu",
        namespace,
        name,
        config["custom_annotations"],
        config["labels"],
    )
    secret.type = config["custom_secret_type"]
    secret = create_template_secret(logger, secret, filename, template)

    apply_owner_reference(secret, config["secret_namespace"], namespace)
    create_secret(logger, secret, config["secret_namespace"])


def update_beta7_secret(spec, status, name, namespace, logger, body, **kwargs):
    template = spec.get("template")
    filename = spec.get("filename")
    config = extract_secret_config(spec)

    old_config, old_secret_name, old_secret_namespace, old_secret_type = (
        parse_old_config(body)
    )

    if old_config is not None and should_recreate_secret(
        old_secret_name,
        config["secret_name"],
        old_secret_namespace,
        config["secret_namespace"],
        old_secret_type,
        config["custom_secret_type"],
    ):
        logger.info("Secret name or namespace changed, let's recreate it")
        delete_managed_secret(old_config["spec"], name, namespace, logger, **kwargs)
        create_managed_secret(spec, name, namespace, logger, body, **kwargs)
        return

    try:
        unlock_bw(logger)
    except BitwardenCommandException as exc:
        if should_skip_due_to_auth_cooldown(exc):
            logger.info(str(exc))
            return
        raise

    secret = kubernetes.client.V1Secret()
    secret.metadata = build_secret_metadata(
        config["secret_name"],
        "bitwarden-template.lerentis.uploadfilter24.eu",
        namespace,
        name,
        config["custom_annotations"],
        config["labels"],
    )
    secret.type = config["custom_secret_type"]
    secret = create_template_secret(logger, secret, filename, template)

    apply_owner_reference(secret, config["secret_namespace"], namespace)
    update_secret(logger, secret, config["secret_namespace"])


@kopf.on.update("bitwarden-template.lerentis.uploadfilter24.eu")
@kopf.timer(
    "bitwarden-template.lerentis.uploadfilter24.eu",
    interval=bw_sync_interval,
    initial_delay=10,
)
def update_managed_secret(spec, status, name, namespace, logger, body, **kwargs):
    template = spec.get("template")
    if template is not None:
        update_beta7_secret(spec, status, name, namespace, logger, body, **kwargs)
        return

    content_def = spec.get("content")
    config = extract_secret_config(spec)

    old_config, old_secret_name, old_secret_namespace, old_secret_type = (
        parse_old_config(body)
    )

    if old_config is not None and should_recreate_secret(
        old_secret_name,
        config["secret_name"],
        old_secret_namespace,
        config["secret_namespace"],
        old_secret_type,
        config["custom_secret_type"],
    ):
        logger.info("Secret name or namespace changed, let's recreate it")
        delete_managed_secret(old_config["spec"], name, namespace, logger, **kwargs)
        create_managed_secret(spec, name, namespace, logger, body, **kwargs)
        return

    try:
        unlock_bw(logger)
    except BitwardenCommandException as exc:
        if should_skip_due_to_auth_cooldown(exc):
            logger.info(str(exc))
            return
        raise

    secret = kubernetes.client.V1Secret()
    secret.metadata = build_secret_metadata(
        config["secret_name"],
        "bitwarden-template.lerentis.uploadfilter24.eu",
        namespace,
        name,
        config["custom_annotations"],
        config["labels"],
    )
    secret.type = config["custom_secret_type"]
    secret = create_template_obj(logger, secret, content_def)

    apply_owner_reference(secret, config["secret_namespace"], namespace)
    update_secret(logger, secret, config["secret_namespace"])


@kopf.on.delete("bitwarden-template.lerentis.uploadfilter24.eu")
def delete_managed_secret(spec, name, namespace, logger, **kwargs):
    config = extract_secret_config(spec)
    delete_secret(logger, config["secret_name"], config["secret_namespace"])
