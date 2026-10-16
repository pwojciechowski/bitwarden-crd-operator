import importlib
import sys
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


def _import_template():
    # template.py decorates kopf handlers at import time; a MagicMock kopf
    # accepts any decorator.
    with patch.dict(sys.modules, {"kopf": MagicMock()}):
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

    def test_failed_item_lookup_fails_rendering(self):
        with patch.dict(
            self._lookup_globals(), {"get_secret_from_bitwarden": lambda *a, **k: None}
        ):
            with self.assertRaises(template.BitwardenCommandException):
                template.render_template(
                    self.logger, '{{ bitwarden_lookup("item-1", "login", "password") }}'
                )


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


if __name__ == "__main__":
    unittest.main()
