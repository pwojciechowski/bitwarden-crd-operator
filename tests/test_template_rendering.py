import importlib
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from jinja2.exceptions import SecurityError


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if "kubernetes" not in sys.modules:
    sys.modules["kubernetes"] = types.SimpleNamespace(
        client=types.SimpleNamespace(CoreV1Api=lambda: None, V1ObjectMeta=lambda **kw: kw)
    )


class TemporaryError(Exception):
    def __init__(self, message="", delay=60):
        super().__init__(message)
        self.delay = delay


def _import_template():
    # template.py decorates kopf handlers at import time; a MagicMock kopf
    # accepts any decorator. Its errors must be real exceptions.
    kopf = MagicMock()
    kopf.TemporaryError = TemporaryError
    with patch.dict(sys.modules, {"kopf": kopf}):
        sys.modules.pop("template", None)
        return importlib.import_module("template")


template = _import_template()


class TemplateRenderingTests(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()

    def test_lookup_templates_still_render(self):
        # A plain function, like the real method: the sandbox refuses to call
        # a MagicMock.
        def fake_lookup(handler, id, scope, field):
            return "s3cret"

        lookup = patch.object(template.BitwardenLookupHandler, "bitwarden_lookup", fake_lookup)
        with lookup:
            rendered = template.render_template(
                self.logger, 'password: {{ bitwarden_lookup("item-1", "login", "password") }}'
            )

        self.assertEqual(rendered, "password: s3cret")

    def test_template_cannot_reach_python_globals_through_the_lookup(self):
        # Unsandboxed, this exposes the utils module's globals (os, environ).
        with self.assertRaises(SecurityError):
            template.render_template(
                self.logger, "{{ bitwarden_lookup.__func__.__globals__ }}"
            )

    def test_template_cannot_walk_object_subclasses(self):
        with self.assertRaises(SecurityError):
            template.render_template(
                self.logger, "{{ ().__class__.__base__.__subclasses__() }}"
            )

    def _lookup_globals(self):
        # lookups.bitwarden_lookup was imported under patch.dict; reach its
        # module globals through the method instead of sys.modules.
        return template.BitwardenLookupHandler.bitwarden_lookup.__globals__

    def test_failed_attachment_lookup_fails_rendering_instead_of_writing_none(self):
        # A timed-out bw returns None; rendering it would put "None" in the Secret.
        with patch.dict(self._lookup_globals(), {"get_attachment": lambda *a: None}):
            with self.assertRaises(template.BitwardenCommandException):
                template.render_template(
                    self.logger, '{{ bitwarden_lookup("item-1", "attachment", "key.pem") }}'
                )

    def test_a_lookup_error_reaches_kopf_unchanged_through_the_render(self):
        # The sandboxed render must not wrap the kopf error: its delay is the
        # retry schedule (Geekvetica#108 B5). Any exception with a delay will do.
        class temporary_error(Exception):
            def __init__(self, message, delay):
                super().__init__(message)
                self.delay = delay

        def missing_item(*args, **kwargs):
            raise temporary_error("Bitwarden item item-1 not found", delay=123)

        with patch.dict(self._lookup_globals(), {"get_secret_from_bitwarden": missing_item}):
            with self.assertRaises(temporary_error) as raised:
                template.render_template(
                    self.logger, '{{ bitwarden_lookup("item-1", "login", "password") }}'
                )
        self.assertEqual(raised.exception.delay, 123)

    def test_missing_custom_field_fails_rendering(self):
        item = {"data": {"fields": [{"name": "present", "value": "v"}]}}
        with patch.dict(
            self._lookup_globals(), {"get_secret_from_bitwarden": lambda *a, **k: item}
        ):
            with self.assertRaises(template.BitwardenCommandException):
                template.render_template(
                    self.logger, '{{ bitwarden_lookup("item-1", "fields", "missing") }}'
                )

    def test_unknown_scope_fails_rendering(self):
        item = {"data": {"login": {"password": "p"}}}
        with patch.dict(
            self._lookup_globals(), {"get_secret_from_bitwarden": lambda *a, **k: item}
        ):
            with self.assertRaises(template.BitwardenCommandException):
                template.render_template(
                    self.logger, '{{ bitwarden_lookup("item-1", "bogus", "x") }}'
                )


class TemplateLimitTests(unittest.TestCase):
    """A broken or hostile BitwardenTemplate must not burn the operator's CPU
    or memory (#108). The real templates are at most 285 characters and
    render to at most 109 (2026-10-21)."""

    def setUp(self):
        self.logger = MagicMock()

    def _refused(self, source):
        with self.assertRaises(TemporaryError) as raised:
            template.render_template(self.logger, source)
        # Only a CR change fixes it: retry at the sync interval, not every 60 s.
        self.assertEqual(raised.exception.delay, template.bw_sync_interval)
        return str(raised.exception)

    def test_a_template_at_the_size_limit_renders(self):
        source = "x" * template.TEMPLATE_MAX_CHARS

        self.assertEqual(template.render_template(self.logger, source), source)

    def test_an_oversized_template_is_refused_before_rendering(self):
        source = "{{ boom() }}" + "x" * template.TEMPLATE_MAX_CHARS

        self.assertIn("template is", self._refused(source))

    def test_output_over_the_limit_is_refused(self):
        source = "{% for i in range(100000) %}0123456789{% endfor %}"

        self.assertIn("rendered output exceeds", self._refused(source))

    def test_output_at_the_limit_renders(self):
        source = "{{ 'x' * %d }}" % template.RENDERED_MAX_CHARS

        self.assertEqual(
            len(template.render_template(self.logger, source)),
            template.RENDERED_MAX_CHARS,
        )

    def test_a_render_stops_after_its_cpu_budget(self):
        # Produces no output, so only the CPU budget stops it. Finite (1e7
        # iterations, seconds when traced), so a regression fails, not hangs.
        source = (
            "{% for i in range(100) %}{% for j in range(100000) %}"
            "{% endfor %}{% endfor %}"
        )
        with patch.object(template, "RENDER_CPU_SECONDS", 0.2):
            started = time.monotonic()
            message = self._refused(source)

        self.assertIn("CPU", message)
        self.assertLess(time.monotonic() - started, 5)

    def test_the_cpu_budget_never_interrupts_a_lookup(self):
        # Raised inside operator or stdlib code (Popen after the fork, a
        # logging lock), it could orphan a bw process outside the command
        # lock. The render stops at the next template line instead.
        finished = []

        def slow_lookup(*args, **kwargs):
            deadline = time.thread_time() + 0.3
            while time.thread_time() < deadline:
                pass
            finished.append(True)
            return {"data": {"login": {"password": "p"}}}

        lookup = patch.dict(
            template.BitwardenLookupHandler.bitwarden_lookup.__globals__,
            {"get_secret_from_bitwarden": slow_lookup},
        )
        with lookup, patch.object(template, "RENDER_CPU_SECONDS", 0.1):
            message = self._refused(
                '{{ bitwarden_lookup("item-1", "login", "password") }}{{ "after" }}'
            )

        self.assertEqual([True], finished)
        self.assertIn("CPU", message)

    def test_a_huge_integer_power_is_refused(self):
        # One C big-integer operation: minutes of CPU that no tracer sees,
        # and Jinja would fold the constant at compile time. (Jinja's ** is
        # left-associative: 10 ** 10 ** 8 is only 10 ** 80.)
        for source in ("{{ 10 ** 100000000 }}", "{{ (10 ** 10) ** 100000000 }}"):
            with self.subTest(source=source):
                self.assertIn("exponent", self._refused(source))

    def test_small_powers_still_render(self):
        self.assertEqual(template.render_template(self.logger, "{{ 2 ** 10 }}"), "1024")

    def test_the_cpu_budget_restores_the_previous_tracer(self):
        def tracer(frame, event, arg):
            return None

        sources = {
            "ok": "ok",
            "cpu": "{% for i in range(100) %}{% for j in range(100000) %}"
            "{% endfor %}{% endfor %}",
            "output": "{% for i in range(100000) %}0123456789{% endfor %}",
        }
        previous = sys.gettrace()
        try:
            for case, source in sources.items():
                with self.subTest(case=case):
                    sys.settrace(tracer)
                    with patch.object(template, "RENDER_CPU_SECONDS", 0.2):
                        try:
                            template.render_template(self.logger, source)
                        except TemporaryError:
                            pass
                    self.assertIs(sys.gettrace(), tracer)
        finally:
            sys.settrace(previous)


if __name__ == "__main__":
    unittest.main()
